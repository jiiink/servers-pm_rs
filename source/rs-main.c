#include "inc.h"
#include <fcntl.h>
#include "kernel/const.h"
#include "kernel/type.h"
#include "kernel/proc.h"

static void boot_image_info_lookup(endpoint_t endpoint, struct boot_image *image, struct boot_image **ip, struct boot_image_priv **pp, struct boot_image_sys **sp, struct boot_image_dev **dp);
static void catch_boot_init_ready(endpoint_t endpoint);
static void get_work(message *m_ptr, int *status_ptr);

static void sef_local_startup(void);
static int sef_cb_init_fresh(int type, sef_init_info_t *info);
static int sef_cb_init_restart(int type, sef_init_info_t *info);
static int sef_cb_init_lu(int type, sef_init_info_t *info);
static int sef_cb_init_response(message *m_ptr);
static int sef_cb_lu_response(message *m_ptr);
static void sef_cb_signal_handler(int signo);
static int sef_cb_signal_manager(endpoint_t target, int signo);

int main(void)
{
    message m;
    int ipc_status;
    int call_nr, who_e, who_p, result, s;

    sef_local_startup();

    if (OK != (s = sys_getmachine(&machine)))
        panic("couldn't get machine info: %d", s);

    while (TRUE) {
        rs_idle_period();
        get_work(&m, &ipc_status);
        who_e = m.m_source;
        if (rs_isokendpt(who_e, &who_p) != OK) {
            panic("message from bogus source: %d", who_e);
        }
        
        call_nr = m.m_type;

        if (is_ipc_notify(ipc_status)) {
            if (who_p == CLOCK) {
                do_period(&m);
                continue;
            } else if (rproc_ptr[who_p] != NULL) {
                rproc_ptr[who_p]->r_alive_tm = m.m_notify.timestamp;
            } else {
                printf("RS: warning: got unexpected notify message from %d\n", m.m_source);
            }
        } else {
            switch (call_nr) {
                case RS_UP:        result = do_up(&m);        break;
                case RS_DOWN:      result = do_down(&m);      break;
                case RS_REFRESH:   result = do_refresh(&m);   break;
                case RS_RESTART:   result = do_restart(&m);   break;
                case RS_SHUTDOWN:  result = do_shutdown(&m);  break;
                case RS_UPDATE:    result = do_update(&m);    break;
                case RS_CLONE:     result = do_clone(&m);     break;
                case RS_UNCLONE:   result = do_unclone(&m);   break;
                case RS_EDIT:      result = do_edit(&m);      break;
                case RS_SYSCTL:    result = do_sysctl(&m);    break;
                case RS_FI:        result = do_fi(&m);        break;
                case RS_GETSYSINFO: result = do_getsysinfo(&m); break;
                case RS_LOOKUP:    result = do_lookup(&m);    break;
                case RS_INIT:      result = do_init_ready(&m); break;
                case RS_LU_PREPARE: result = do_upd_ready(&m); break;
                default: 
                    printf("RS: warning: got unexpected request %d from %d\n", m.m_type, m.m_source);
                    result = ENOSYS;
            }

            if (result != EDONTREPLY) {
                m.m_type = result;
                reply(who_e, NULL, &m);
            }
        }
    }
}

static void sef_local_startup(void)
{
    sef_setcb_init_fresh(sef_cb_init_fresh);
    sef_setcb_init_restart(sef_cb_init_restart);
    sef_setcb_init_lu(sef_cb_init_lu);
    sef_setcb_init_response(sef_cb_init_response);
    sef_setcb_lu_response(sef_cb_lu_response);
    sef_setcb_signal_handler(sef_cb_signal_handler);
    sef_setcb_signal_manager(sef_cb_signal_manager);
    sef_startup();
}

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
    struct boot_image *ip;
    int s, i, nr_image_srvs, nr_image_priv_srvs, nr_uncaught_init_srvs;
    struct rproc *rp;
    struct boot_image image[NR_BOOT_PROCS];
    struct boot_image_priv *boot_image_priv;
    int ipc_to;
    int *calls;
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = { NULL_C };

    env_parse("rs_verbose", "d", 0, &rs_verbose, 0, 1);

    if ((s = sys_getinfo(GET_HZ, &system_hz, sizeof(system_hz), 0, 0)) != OK)
        panic("Cannot get system timer frequency\n");

    rinit.rproctab_gid = cpf_grant_direct(ANY, (vir_bytes)rprocpub, sizeof(rprocpub), CPF_READ);
    if (!GRANT_VALID(rinit.rproctab_gid)) {
        panic("unable to create rprocpub table grant: %d", rinit.rproctab_gid);
    }

    RUPDATE_INIT();
    shutting_down = FALSE;

    if ((s = sys_getimage(image)) != OK) {
        panic("unable to get copy of boot image table: %d", s);
    }

    nr_image_srvs = 0;
    for (i = 0; i < NR_BOOT_PROCS; i++) {
        ip = &image[i];
        if (!iskerneln(_ENDPOINT_P(ip->endpoint))) {
            nr_image_srvs++;
        }
    }

    nr_image_priv_srvs = 0;
    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (!iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            nr_image_priv_srvs++;
        }
    }
    if (nr_image_srvs != nr_image_priv_srvs) {
        panic("boot image table and boot image priv table mismatch");
    }

    for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        rp->r_flags = 0;
        rp->r_init_err = ERESTART;
        rp->r_pub = &rprocpub[rp - rproc];
        rp->r_pub->in_use = FALSE;
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
    }

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (!iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            boot_image_info_lookup(boot_image_priv->endpoint, image, &ip, NULL, NULL, NULL);
            rp = &rproc[boot_image_priv - boot_image_priv_table];
            rp->r_priv.s_id = static_priv_id(_ENDPOINT_P(boot_image_priv->endpoint));
            rp->r_priv.s_flags = boot_image_priv->flags;
            rp->r_priv.s_init_flags = SRV_OR_USR(rp, SRV_I, USR_I);
            rp->r_priv.s_trap_mask = SRV_OR_USR(rp, SRV_T, USR_T);
            ipc_to = SRV_OR_USR(rp, SRV_M, USR_M);
            fill_send_mask(&rp->r_priv.s_ipc_to, ipc_to == ALL_M);
            rp->r_priv.s_sig_mgr = SRV_OR_USR(rp, SRV_SM, USR_SM);
            rp->r_priv.s_bak_sig_mgr = NONE;
            calls = SRV_OR_USR(rp, SRV_KC, USR_KC) == ALL_C ? all_c : no_c;
            fill_call_mask(calls, NR_SYS_CALLS, rp->r_priv.s_k_call_mask, KERNEL_CALL, TRUE);
            if (boot_image_priv->endpoint != RS_PROC_NR && boot_image_priv->endpoint != VM_PROC_NR) {
                if ((s = sys_privctl(ip->endpoint, SYS_PRIV_SET_SYS, &(rp->r_priv))) != OK) {
                    panic("unable to set privilege structure: %d", s);
                }
            }
            if ((s = sys_getpriv(&(rp->r_priv), ip->endpoint)) != OK) {
                panic("unable to synch privilege structure: %d", s);
            }
            strlcpy(rp->r_cmd, ip->proc_name, sizeof(rp->r_cmd));
            rp->r_script[0] = '\0';
            build_cmd_dep(rp);
            strlcpy(rp->r_pub->proc_name, ip->proc_name, sizeof(rp->r_pub->proc_name));
            calls = SRV_OR_USR(rp, SRV_VC, USR_VC) == ALL_C ? all_c : no_c;
            fill_call_mask(calls, NR_VM_CALLS, rp->r_pub->vm_call_mask, VM_RQ_BASE, TRUE);
            rp->r_scheduler = SRV_OR_USR(rp, SRV_SCH, USR_SCH);
            rp->r_priority = SRV_OR_USR(rp, SRV_Q, USR_Q);
            rp->r_quantum = SRV_OR_USR(rp, SRV_QT, USR_QT);
            rp->r_pub->endpoint = ip->endpoint;
            rp->r_old_rp = NULL;
            rp->r_new_rp = NULL;
            rp->r_prev_rp = NULL;
            rp->r_next_rp = NULL;
            rp->r_uid = 0;
            rp->r_check_tm = 0;
            rp->r_alive_tm = getticks();
            rp->r_stop_tm = 0;
            rp->r_asr_count = 0;
            rp->r_restarts = 0;
            rp->r_period = 0;
            rp->r_exec = NULL;
            rp->r_exec_len = 0;
            rp->r_flags = RS_IN_USE | RS_ACTIVE;
            rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = rp;
            rp->r_pub->in_use = TRUE;
        }
    }

    nr_uncaught_init_srvs = 0;
    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (!iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            rp = &rproc[boot_image_priv - boot_image_priv_table];
            if (boot_image_priv->endpoint == RS_PROC_NR || boot_image_priv->endpoint == VM_PROC_NR) {
                if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
                    panic("unable to initialize %d: %d", boot_image_priv->endpoint, s);
                }
                if (boot_image_priv->endpoint != RS_PROC_NR) {
                    nr_uncaught_init_srvs++;
                }
                continue;
            }
            if ((s = sched_init_proc(rp)) != OK) {
                panic("unable to initialize scheduling: %d", s);
            }
            if ((s = sys_privctl(rp->r_pub->endpoint, SYS_PRIV_ALLOW, NULL)) != OK) {
                panic("unable to initialize privileges: %d", s);
            }
            if (boot_image_priv->flags & SYS_PROC) {
                if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
                    panic("unable to initialize service: %d", s);
                }
                if (rp->r_pub->sys_flags & SF_SYNCH_BOOT) {
                    catch_boot_init_ready(rp->r_pub->endpoint);
                } else {
                    nr_uncaught_init_srvs++;
                }
            }
        }
    }

    while (nr_uncaught_init_srvs) {
        catch_boot_init_ready(ANY);
        nr_uncaught_init_srvs--;
    }

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (!iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            rp = &rproc[boot_image_priv - boot_image_priv_table];
            rp->r_pid = getnpid(rp->r_pub->endpoint);
            if (rp->r_pid < 0) {
                panic("unable to get pid: %d", rp->r_pid);
            }
        }
    }

    if (OK != (s = sys_setalarm(RS_DELTA_T, 0)))
        panic("couldn't set alarm: %d", s);

    return (OK);
}

static int sef_cb_init_restart(int type, sef_init_info_t *info)
{
    int r;
    struct rproc *old_rs_rp, *new_rs_rp;

    assert(info->endpoint == RS_PROC_NR);

    r = SEF_CB_INIT_RESTART_STATEFUL(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_RESTART_STATEFUL failed: %d\n", r);
        return r;
    }

    old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
    if (rs_verbose)
        printf("RS: %s is the new RS after restart\n", srv_to_string(new_rs_rp));

    if (SRV_IS_UPDATING(old_rs_rp)) {
        end_update(ERESTART, RS_REPLY);
    }

    r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if (r != OK) {
        printf("update_service failed: %d\n", r);
        return r;
    }

    r = init_service(new_rs_rp, SEF_INIT_RESTART, 0);
    if (r != OK) {
        printf("init_service failed: %d\n", r);
        return r;
    }

    if (OK != (r = sys_setalarm(RS_DELTA_T, 0)))
        panic("couldn't set alarm: %d", r);

    return OK;
}

static int sef_cb_init_lu(int type, sef_init_info_t *info)
{
    int r;
    struct rproc *old_rs_rp, *new_rs_rp;

    assert(info->endpoint == RS_PROC_NR);

    sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);
    r = SEF_CB_INIT_LU_DEFAULT(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_LU_DEFAULT failed: %d\n", r);
        return r;
    }

    old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
    if (rs_verbose)
        printf("RS: %s is the new RS after live update\n", srv_to_string(new_rs_rp));

    r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if (r != OK) {
        printf("update_service failed: %d\n", r);
        return r;
    }

    assert(RUPDATE_IS_UPDATING());
    assert(RUPDATE_IS_INITIALIZING());
    assert(rupdate.num_rpupds > 0);
    assert(rupdate.num_init_ready_pending > 0);

    return OK;
}

int sef_cb_init_response(message *m_ptr)
{
    int r;

    r = m_ptr->m_rs_init.result;
    if (r != OK) {
        return r;
    }

    r = do_init_ready(m_ptr);

    if (r == EDONTREPLY) {
        r = OK;
    }
    return r;
}

int sef_cb_lu_response(message *m_ptr)
{
    int r;

    r = do_upd_ready(m_ptr);

    if (r == EDONTREPLY) {
        r = EGENERIC;
    }
    return r;
}

static void sef_cb_signal_handler(int signo)
{
    if (signo == SIGCHLD) {
        do_sigchld();
    } else if (signo == SIGTERM) {
        do_shutdown(NULL);
    }
}

static int sef_cb_signal_manager(endpoint_t target, int signo)
{
    int target_p;
    struct rproc *rp;
    message m;

    if (rs_isokendpt(target, &target_p) != OK || rproc_ptr[target_p] == NULL) {
        if (rs_verbose)
            printf("RS: ignoring spurious signal %d for process %d\n", signo, target);
        return OK;
    }
    rp = rproc_ptr[target_p];

    if ((rp->r_flags & RS_TERMINATED) && !(rp->r_flags & RS_EXITING)) {
        return EDEADEPT;
    }

    if (!(rp->r_flags & RS_ACTIVE) && !(rp->r_flags & RS_EXITING)) {
        if (rs_verbose)
            printf("RS: ignoring signal %d for inactive %s\n", signo, srv_to_string(rp));
        return OK;
    }

    if (rs_verbose)
        printf("RS: %s got %s signal %d\n", srv_to_string(rp), SIGS_IS_TERMINATION(signo) ? "termination" : "non-termination", signo);

    if (SIGS_IS_STACKTRACE(signo)) {
        sys_diagctl_stacktrace(target);
    }

    if (SIGS_IS_TERMINATION(signo)) {
        rp->r_flags |= RS_TERMINATED;
        terminate_service(rp);
        rs_idle_period();
        return EDEADEPT;
    }

    if (rp->r_pub->endpoint != VM_PROC_NR) {
        m.m_type = SIGS_SIGNAL_RECEIVED;
        m.m_pm_lsys_sigs_signal.num = signo;
        rs_asynsend(rp, &m, 1);
    }

    return OK;
}

static void boot_image_info_lookup(endpoint_t endpoint, struct boot_image *image, struct boot_image **ip, struct boot_image_priv **pp, struct boot_image_sys **sp, struct boot_image_dev **dp)
{
    int i;

    if (ip) {
        for (i = 0; i < NR_BOOT_PROCS; i++) {
            if (image[i].endpoint == endpoint) {
                *ip = &image[i];
                break;
            }
        }
        if (i == NR_BOOT_PROCS) {
            panic("boot image table lookup failed");
        }
    }

    if (pp) {
        for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
            if (boot_image_priv_table[i].endpoint == endpoint) {
                *pp = &boot_image_priv_table[i];
                break;
            }
        }
        if (i == NULL_BOOT_NR) {
            panic("boot image priv table lookup failed");
        }
    }

    if (sp) {
        for (i = 0; boot_image_sys_table[i].endpoint != DEFAULT_BOOT_NR; i++) {
            if (boot_image_sys_table[i].endpoint == endpoint) {
                *sp = &boot_image_sys_table[i];
                break;
            }
        }
        if (boot_image_sys_table[i].endpoint == DEFAULT_BOOT_NR) {
            *sp = &boot_image_sys_table[i];
        }
    }

    if (dp) {
        for (i = 0; boot_image_dev_table[i].endpoint != DEFAULT_BOOT_NR; i++) {
            if (boot_image_dev_table[i].endpoint == endpoint) {
                *dp = &boot_image_dev_table[i];
                break;
            }
        }
        if (boot_image_dev_table[i].endpoint == DEFAULT_BOOT_NR) {
            *dp = &boot_image_dev_table[i];
        }
    }
}

static void catch_boot_init_ready(endpoint_t endpoint)
{
    int r, ipc_status;
    message m;
    struct rproc *rp;
    int result;

    if ((r = sef_receive_status(endpoint, &m, &ipc_status)) != OK) {
        panic("unable to receive init reply: %d", r);
    }
    if (m.m_type != RS_INIT) {
        panic("unexpected reply from service: %d", m.m_source);
    }
    result = m.m_rs_init.result;
    rp = rproc_ptr[_ENDPOINT_P(m.m_source)];

    if (result != OK) {
        panic("unable to complete init for service: %d", m.m_source);
    }

    if (m.m_source != VM_PROC_NR) {
        m.m_type = OK;
        reply(m.m_source, rp, &m);
    }

    rp->r_flags &= ~RS_INITIALIZING;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();
}

static void get_work(message *m_ptr, int *status_ptr)
{
    int r;
    if (OK != (r = sef_receive_status(ANY, m_ptr, status_ptr)))
        panic("sef_receive_status failed: %d", r);
}