#include <paths.h>
#include <sys/exec_elf.h>
#include "inc.h"
#include "kernel/proc.h"

static int run_script(struct rproc *rp);

static int caller_is_root(endpoint_t endpoint) {
    uid_t euid = getnuid(endpoint);
    if (rs_verbose && euid != 0) {
        printf("RS: got unauthorized request from endpoint %d\n", endpoint);
    }
    return euid == 0;
}

static int caller_can_control(endpoint_t endpoint, struct rproc *target_rp) {
    struct rproc *rp;
    char *proc_name = target_rp->r_pub->proc_name;
    int control_allowed = 0, c;

    for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        if ((rp->r_flags & RS_IN_USE) && rp->r_pub->endpoint == endpoint) {
            break;
        }
    }
    if (rp == END_RPROC_ADDR) return 0;

    for (c = 0; c < rp->r_nr_control; c++) {
        if (strcmp(rp->r_control[c], proc_name) == 0) {
            control_allowed = 1;
            break;
        }
    }

    if (rs_verbose) {
        printf("RS: allowing %u control over %s via policy: %s\n",
               endpoint, target_rp->r_pub->label, control_allowed ? "yes" : "no");
    }

    return control_allowed;
}

int check_call_permission(endpoint_t caller, int call, struct rproc *rp) {
    struct rprocpub *rpub;
    int call_allowed = caller_is_root(caller) || (rp && caller_can_control(caller, rp));
    
    if (!call_allowed) return EPERM;

    if (rp) {
        rpub = rp->r_pub;

        if (!(rp->r_priv.s_flags & SYS_PROC) && call != RS_EDIT) return EPERM;
        if (RUPDATE_IS_UPDATING() || (rp->r_flags & (RS_LATEREPLY | RS_INITIALIZING))) return EBUSY;
        if ((rp->r_flags & RS_TERMINATED) && call != RS_DOWN && call != RS_RESTART) return EPERM;
        if ((rpub->sys_flags & SF_CORE_SRV) && call == RS_DOWN) return EPERM;
    }

    return OK;
}

int copy_rs_start(endpoint_t src_e, char *src_rs_start, struct rs_start *dst_rs_start) {
    return sys_datacopy(src_e, (vir_bytes) src_rs_start,
                        SELF, (vir_bytes) dst_rs_start, sizeof(struct rs_start));
}

int copy_label(endpoint_t src_e, char *src_label, size_t src_len, char *dst_label, size_t dst_len) {
    int s, len = MIN(dst_len - 1, src_len);

    s = sys_datacopy(src_e, (vir_bytes) src_label, SELF, (vir_bytes) dst_label, len);
    if (s != OK) return s;

    dst_label[len] = 0;
    return OK;
}

int init_state_data(endpoint_t src_e, int prepare_state, struct rs_state_data *src_rs_state_data,
                    struct rs_state_data *dst_rs_state_data) {
    struct rs_ipc_filter_el rs_ipc_filter[IPCF_MAX_ELEMENTS] = {0};
    ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS];
    size_t ipcf_els_buff_size;

    if (src_rs_state_data->size != sizeof(struct rs_state_data)) return E2BIG;

    if (prepare_state == SEF_LU_STATE_EVAL) {
        if (!src_rs_state_data->eval_len || !src_rs_state_data->eval_addr) return EINVAL;

        dst_rs_state_data->eval_addr = malloc(src_rs_state_data->eval_len + 1);
        dst_rs_state_data->eval_len = src_rs_state_data->eval_len;

        if (!dst_rs_state_data->eval_addr) return ENOMEM;

        int s = sys_datacopy(src_e, (vir_bytes) src_rs_state_data->eval_addr, SELF, (vir_bytes) dst_rs_state_data->eval_addr, dst_rs_state_data->eval_len);
        if (s != OK) return s;

        *((char *) dst_rs_state_data->eval_addr + dst_rs_state_data->eval_len) = '\0';
        dst_rs_state_data->size = src_rs_state_data->size;
    }

    dst_rs_state_data->ipcf_els = NULL;

    if (src_rs_state_data->ipcf_els_size % sizeof(rs_ipc_filter) != 0) return E2BIG;

    int num_ipc_filters = src_rs_state_data->ipcf_els_size / sizeof(rs_ipc_filter);
    ipcf_els_buff_size = sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS * num_ipc_filters + (src_e == VM_PROC_NR ? sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS : 0);
    ipcf_els_buff = malloc(ipcf_els_buff_size);

    if (!ipcf_els_buff) return ENOMEM;

    memset(ipcf_els_buff, 0, ipcf_els_buff_size);

    for (int i = 0; i < num_ipc_filters; i++) {
        int s = sys_datacopy(src_e, (vir_bytes) src_rs_state_data->ipcf_els[i], SELF, (vir_bytes) rs_ipc_filter, sizeof(rs_ipc_filter));
        if (s != OK) return s;

        for (int j = 0; j < IPCF_MAX_ELEMENTS && rs_ipc_filter[j].flags; j++) {
            endpoint_t m_source = 0;
            int flags = rs_ipc_filter[j].flags;
            int m_type = flags & IPCF_MATCH_M_TYPE ? rs_ipc_filter[j].m_type : 0;

            if (flags & IPCF_MATCH_M_SOURCE) {
                if (ds_retrieve_label_endpt(rs_ipc_filter[j].m_label, &m_source) != OK) {
                    char *buff;
                    errno = 0;
                    m_source = strtol(rs_ipc_filter[j].m_label, &buff, 10);
                    if (errno || strcmp(buff, "")) return ESRCH;
                }
            }
            ipcf_els_buff[i][j].flags = flags;
            ipcf_els_buff[i][j].m_source = m_source;
            ipcf_els_buff[i][j].m_type = m_type;
        }
    }

    if (src_e == VM_PROC_NR) {
        ipcf_els_buff[num_ipc_filters][0].flags = IPCF_EL_WHITELIST | IPCF_MATCH_M_SOURCE | IPCF_MATCH_M_TYPE;
        ipcf_els_buff[num_ipc_filters][0].m_source = RS_PROC_NR;
        ipcf_els_buff[num_ipc_filters][0].m_type = VM_RS_UPDATE;
    }

    dst_rs_state_data->ipcf_els = ipcf_els_buff;
    dst_rs_state_data->ipcf_els_size = ipcf_els_buff_size;

    return OK;
}

void build_cmd_dep(struct rproc *rp) {
    int arg_count;
    char *cmd_ptr = rp->r_args;

    strcpy(rp->r_args, rp->r_cmd);
    arg_count = 0;
    rp->r_argv[arg_count++] = rp->r_args;

    while (*cmd_ptr != '\0') {
        if (*cmd_ptr == ' ') {
            *cmd_ptr = '\0';
            while (*++cmd_ptr == ' ');
            if (*cmd_ptr == '\0') break;

            if (arg_count >= ARGV_ELEMENTS - 1) {
                printf("RS: build_cmd_dep: too many args\n");
                break;
            }
            rp->r_argv[arg_count++] = cmd_ptr;
        }
        cmd_ptr++;
    }
    rp->r_argv[arg_count] = NULL;
    rp->r_argc = arg_count;
}

void end_srv_init(struct rproc *rp) {
    late_reply(rp, OK);

    if (rp->r_prev_rp) {
        if (SRV_IS_UPD_SCHEDULED(rp->r_prev_rp)) {
            rupdate_upd_move(rp->r_prev_rp, rp);
        }
        cleanup_service(rp->r_prev_rp);
        rp->r_prev_rp = NULL;
        rp->r_restarts += 1;

        if (rs_verbose) printf("RS: %s completed restart\n", srv_to_string(rp));
    }
    rp->r_next_rp = NULL;
}

int kill_service_debug(char *file, int line, struct rproc *rp, char *errstr, int err) {
    if (errstr && !shutting_down) {
        printf("RS: %s (error %d)\n", errstr, err);
    }
    rp->r_flags |= RS_EXITING;
    crash_service_debug(file, line, rp);
    return err;
}

int crash_service_debug(char *file, int line, struct rproc *rp) {
    struct rprocpub *rpub = rp->r_pub;

    if (rs_verbose) {
        printf("RS: %s %skilled at %s:%d\n", srv_to_string(rp),
               rp->r_flags & RS_EXITING ? "lethally " : "", file, line);
    }

    if (rpub->endpoint == RS_PROC_NR) {
        exit(1);
    }

    return sys_kill(rpub->endpoint, SIGKILL);
}

void cleanup_service_debug(char *file, int line, struct rproc *rp) {
    struct rprocpub *rpub = rp->r_pub;
    int detach, cleanup_script = rp->r_flags & RS_CLEANUP_SCRIPT;
    rp->r_flags &= ~RS_CLEANUP_SCRIPT;

    if (!(rp->r_flags & RS_DEAD)) {
        if (rs_verbose)
            printf("RS: %s marked for cleanup at %s:%d\n", srv_to_string(rp), file, line);

        if (rp->r_next_rp) rp->r_next_rp->r_prev_rp = NULL;
        if (rp->r_prev_rp) rp->r_prev_rp->r_next_rp = NULL;
        if (rp->r_new_rp) rp->r_new_rp->r_old_rp = NULL;
        if (rp->r_old_rp) rp->r_old_rp->r_new_rp = NULL;
        rp->r_flags |= RS_DEAD;

        sys_privctl(rpub->endpoint, SYS_PRIV_DISALLOW, NULL);
        sys_privctl(rpub->endpoint, SYS_PRIV_CLEAR_IPC_REFS, NULL);

        toggle_rs_active_flag(rp, 0);
        late_reply(rp, OK);

        return;
    }

    if (rs_verbose)
        printf("RS: %s cleaned up at %s:%d\n", srv_to_string(rp), file, line);

    stop_service_cleanup_procs(rp);

    if (cleanup_script) {
        int s = run_script(rp);
        if (s != OK) {
            printf("RS: warning: cannot run cleanup script: %d\n", s);
        }
    }

    if (!(rp->r_flags & RS_REINCARNATE)) detach_service(rp);
    else free_slot(rp);
}

void detach_service_debug(char *file, int line, struct rproc *rp) {
    static unsigned long detach_counter = 0;
    struct rprocpub *rpub = rp->r_pub;

    rpub->label[RS_MAX_LABEL_LEN - 1] = '\0';
    snprintf(rpub->label, RS_MAX_LABEL_LEN, "%lu.%s", ++detach_counter, rpub->label);

    if (rs_verbose)
        printf("RS: %s detached at %s:%d\n", srv_to_string(rp), file, line);

    rp->r_flags = RS_IN_USE | RS_ACTIVE;
    rpub->sys_flags &= ~(SF_CORE_SRV | SF_DET_RESTART);
    rp->r_period = 0;
    rpub->dev_nr = 0;
    rpub->nr_domain = 0;
    sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
}

int create_service(struct rproc *rp) {
    int child_proc_nr_e, child_proc_nr_n;
    pid_t child_pid;
    int s, use_copy, has_replica;
    extern char **environ;
    struct rprocpub *rpub;

    rpub = rp->r_pub;
    use_copy = (rpub->sys_flags & SF_USE_COPY);
    has_replica = (rp->r_old_rp || (rp->r_prev_rp && !(rp->r_prev_rp->r_flags & RS_TERMINATED)));

    if (!has_replica && (rpub->sys_flags & SF_NEED_REPL)) {
        printf("RS: unable to create service '%s' without a replica\n", rpub->label);
        cleanup_service_now(rp);
        return EPERM;
    }

    if (!use_copy && (rpub->sys_flags & SF_NEED_COPY)) {
        printf("RS: unable to create service '%s' without an in-memory copy\n", rpub->label);
        cleanup_service_now(rp);
        return EPERM;
    }

    if (!use_copy && !strcmp(rp->r_cmd, "")) {
        printf("RS: unable to create service '%s' without a copy or command\n", rpub->label);
        cleanup_service_now(rp);
        return EPERM;
    }

    if (rs_verbose)
        printf("RS: forking child with srv_fork()...\n");

    child_pid = srv_fork(rp->r_uid, 0);
    if (child_pid < 0) {
        printf("RS: srv_fork() failed (error %d)\n", child_pid);
        cleanup_service_now(rp);
        return child_pid;
    }

    if ((s = getprocnr(child_pid, &child_proc_nr_e)) != 0)
        panic("unable to get child endpoint: %d", s);

    child_proc_nr_n = _ENDPOINT_P(child_proc_nr_e);
    rp->r_flags = RS_IN_USE;
    rpub->endpoint = child_proc_nr_e;
    rp->r_pid = child_pid;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();
    rp->r_stop_tm = 0;
    rp->r_backoff = 0;
    rproc_ptr[child_proc_nr_n] = rp;
    rpub->in_use = TRUE;

    if ((s = sys_privctl(child_proc_nr_e, SYS_PRIV_SET_SYS, &rp->r_priv)) != OK
        || (s = sys_getpriv(&rp->r_priv, child_proc_nr_e)) != OK) {
        printf("RS: unable to set privilege structure: %d\n", s);
        cleanup_service_now(rp);
        return ENOMEM;
    }

    if ((s = sched_init_proc(rp)) != OK) {
        printf("RS: unable to start scheduling: %d\n", s);
        cleanup_service_now(rp);
        return s;
    }

    if (use_copy) {
        if (rs_verbose)
            printf("RS: %s uses an in-memory copy\n", srv_to_string(rp));
    } else {
        if ((s = read_exec(rp)) != OK) {
            printf("RS: read_exec failed: %d\n", s);
            cleanup_service_now(rp);
            return s;
        }
    }

    if (rs_verbose)
        printf("RS: execing child with srv_execve()...\n");

    s = srv_execve(child_proc_nr_e, rp->r_exec, rp->r_exec_len, rpub->proc_name, rp->r_argv, environ);

    if (s != OK) {
        printf("RS: srv_execve failed: %d\n", s);
        cleanup_service_now(rp);
        return s;
    }

    if (!use_copy) free_exec(rp);

    setuid(0);

    if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
        if (rs_verbose)
            printf("RS: pinning memory of RS instance %s\n", srv_to_string(rp));

        s = vm_memctl(rpub->endpoint, VM_RS_MEM_PIN, 0, 0);
        if (s != OK) {
            printf("vm_memctl failed: %d\n", s);
            cleanup_service_now(rp);
            return s;
        }
    }

    if (rp->r_priv.s_flags & VM_SYS_PROC) {
        if (rs_verbose)
            printf("RS: informing VM of instance %s\n", srv_to_string(rp));

        s = vm_memctl(rpub->endpoint, VM_RS_MEM_MAKE_VM, 0, 0);
        if (s != OK) {
            printf("vm_memctl failed: %d\n", s);
            cleanup_service_now(rp);
            return s;
        }

        struct rproc *rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
        struct rproc **rs_rps;
        int nr_rs_rps;
        get_service_instances(rs_rp, &rs_rps, &nr_rs_rps);
        for (int i = 0; i < nr_rs_rps; i++) {
            vm_memctl(rs_rps[i]->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
        }
    }

    if ((s = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0], TRUE)) != OK) {
        printf("RS: vm_set_priv failed: %d\n", s);
        cleanup_service_now(rp);
        return s;
    }

    if (rs_verbose)
        printf("RS: %s created\n", srv_to_string(rp));

    return OK;
}

int clone_service(struct rproc *rp, int instance_flag, int init_flags) {
    struct rproc *replica_rp;
    struct rprocpub *replica_rpub;
    struct rproc **rp_link, **replica_link, *rs_rp;
    int rs_flags, r;

    if (rs_verbose)
        printf("RS: %s creating a replica\n", srv_to_string(rp));

    if (rp->r_pub->endpoint == VM_PROC_NR && instance_flag == LU_SYS_PROC
        && rp->r_next_rp) {
        cleanup_service_now(rp->r_next_rp);
        rp->r_next_rp = NULL;
    }

    if ((r = clone_slot(rp, &replica_rp)) != OK) return r;

    replica_rpub = replica_rp->r_pub;

    if (instance_flag == LU_SYS_PROC) {
        rp_link = &rp->r_new_rp;
        replica_link = &replica_rp->r_old_rp;
    } else {
        rp_link = &rp->r_next_rp;
        replica_link = &replica_rp->r_prev_rp;
    }

    replica_rp->r_priv.s_flags |= instance_flag;
    replica_rp->r_priv.s_init_flags |= init_flags;

    *rp_link = replica_rp;
    *replica_link = rp;

    r = create_service(replica_rp);
    if (r != OK) {
        *rp_link = NULL;
        return r;
    }

    rs_flags = (ROOT_SYS_PROC | RST_SYS_PROC);
    if ((replica_rp->r_priv.s_flags & rs_flags) == rs_flags) {
        rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];

        r = update_sig_mgrs(rs_rp, SELF, replica_rpub->endpoint);
        if (r == OK) {
            r = update_sig_mgrs(replica_rp, SELF, NONE);
        }
        if (r != OK) {
            *rp_link = NULL;
            return kill_service(replica_rp, "update_sig_mgrs failed", r);
        }
    }

    return OK;
}

int publish_service(struct rproc *rp) {
    int r;
    struct rprocpub *rpub = rp->r_pub;
    struct rs_pci pci_acl;
    message m;
    endpoint_t ep;

    r = ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);
    if (r != OK) return kill_service(rp, "ds_publish_label call failed", r);

    if (rpub->dev_nr > 0 || rpub->nr_domain > 0) {
        setuid(0);
        r = mapdriver(rpub->label, rpub->dev_nr, rpub->domain, rpub->nr_domain);
        if (r != OK) return kill_service(rp, "couldn't map driver", r);
    }

#if USE_PCI
    if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
        pci_acl = rpub->pci_acl;
        strcpy(pci_acl.rsp_label, rpub->label);
        pci_acl.rsp_endpoint = rpub->endpoint;

        r = pci_set_acl(&pci_acl);
        if (r != OK) return kill_service(rp, "pci_set_acl call failed", r);
    }
#endif

    if (rpub->devman_id != 0) {
        r = ds_retrieve_label_endpt("devman", &ep);
        if (r != OK) return kill_service(rp, "devman not running?", r);

        m.m_type = DEVMAN_BIND;
        m.DEVMAN_ENDPOINT = rpub->endpoint;
        m.DEVMAN_DEVICE_ID = rpub->devman_id;
        r = ipc_sendrec(ep, &m);
        if (r != OK || m.DEVMAN_RESULT != OK) return kill_service(rp, "devman bind device failed", r);
    }

    if (rs_verbose) printf("RS: %s published\n", srv_to_string(rp));
    return OK;
}

int unpublish_service(struct rproc *rp) {
    struct rprocpub *rpub = rp->r_pub;
    int r, result = OK;
    message m;
    endpoint_t ep;

    r = ds_delete_label(rpub->label);
    if (r != OK && !shutting_down) {
        printf("RS: ds_delete_label call failed (error %d)\n", r);
        result = r;
    }

#if USE_PCI
    if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
        r = pci_del_acl(rpub->endpoint);
        if (r != OK && !shutting_down) {
            printf("RS: pci_del_acl call failed (error %d)\n", r);
            result = r;
        }
    }
#endif

    if (rpub->devman_id != 0) {
        r = ds_retrieve_label_endpt("devman", &ep);
        if (r != OK) printf("RS: devman not running?");
        else {
            m.m_type = DEVMAN_UNBIND;
            m.DEVMAN_ENDPOINT = rpub->endpoint;
            m.DEVMAN_DEVICE_ID = rpub->devman_id;
            r = ipc_sendrec(ep, &m);
            if (r != OK || m.DEVMAN_RESULT != OK) printf("RS: devman unbind device failed");
        }
    }

    if (rs_verbose) printf("RS: %s unpublished\n", srv_to_string(rp));
    return result;
}

int run_service(struct rproc *rp, int init_type, int init_flags) {
    struct rprocpub *rpub = rp->r_pub;
    int s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
    if (s != OK) return kill_service(rp, "unable to allow the service to run", s);

    s = init_service(rp, init_type, init_flags);
    if (s != OK) return kill_service(rp, "unable to initialize service", s);

    if (rs_verbose) printf("RS: %s allowed to run\n", srv_to_string(rp));
    return OK;
}

int start_service(struct rproc *rp, int init_flags) {
    struct rprocpub *rpub = rp->r_pub;
    int r = create_service(rp);
    if (r != OK) return r;
    activate_service(rp, NULL);
    r = publish_service(rp);
    if (r != OK) return r;

    r = run_service(rp, SEF_INIT_FRESH, init_flags);
    if (r != OK) return r;

    if (rs_verbose) printf("RS: %s started with major %d\n", srv_to_string(rp), rpub->dev_nr);
    return OK;
}

void stop_service(struct rproc *rp, int how) {
    struct rprocpub *rpub = rp->r_pub;

    if (rs_verbose) printf("RS: %s signaled with SIGTERM\n", srv_to_string(rp));

    int signo = rpub->endpoint != RS_PROC_NR ? SIGTERM : SIGHUP;
    rp->r_flags |= how;
    sys_kill(rpub->endpoint, signo);
    rp->r_stop_tm = getticks();
}

void activate_service(struct rproc *rp, struct rproc *ex_rp) {
    if (ex_rp && (ex_rp->r_flags & RS_ACTIVE)) {
        ex_rp->r_flags &= ~RS_ACTIVE;
        if (rs_verbose) printf("RS: %s becomes inactive\n", srv_to_string(ex_rp));
    }

    if (!(rp->r_flags & RS_ACTIVE)) {
        rp->r_flags |= RS_ACTIVE;
        if (rs_verbose) printf("RS: %s becomes active\n", srv_to_string(rp));
    }
}

void reincarnate_service(struct rproc *old_rp) {
    struct rproc *rp;
    int r = clone_slot(old_rp, &rp);
    if (r != OK) {
        printf("RS: Failed to clone the slot: %d\n", r);
        return;
    }

    rp->r_flags = RS_IN_USE;
    rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = NULL;
    rp->r_restarts++;
    start_service(rp, SEF_INIT_FRESH);
}

void terminate_service(struct rproc *rp) {
    struct rproc **rps;
    struct rprocpub *rpub = rp->r_pub;
    int nr_rps, norestart = !(rp->r_flags & RS_EXITING) && (rp->r_pub->sys_flags & SF_NORESTART), i, r;

    if (rs_verbose) printf("RS: %s terminated\n", srv_to_string(rp));

    if (rp->r_flags & RS_INITIALIZING) {
        if (SRV_IS_UPDATING(rp)) {
            printf("RS: update failed: state transfer failed. Rolling back...\n");
            end_update(rp->r_init_err, RS_REPLY);
            rp->r_init_err = ERESTART;
            return;
        }

        if (rpub->sys_flags & SF_NO_BIN_EXP) {
            rp->r_flags |= RS_REFRESHING;
        } else {
            rp->r_flags |= RS_EXITING;
        }
    }

    if (RUPDATE_IS_UPDATING()) {
        printf("RS: aborting the update after a crash...\n");
        abort_update_proc(ERESTART);
    }

    if (norestart) {
        rp->r_flags |= RS_EXITING;
        if ((rpub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART)) {
            rp->r_flags |= RS_CLEANUP_DETACH;
        }
        if (rp->r_script[0] != '\0') {
            rp->r_flags |= RS_CLEANUP_SCRIPT;
        }
    }

    if (rp->r_flags & RS_EXITING) {
        if ((rpub->sys_flags & SF_CORE_SRV) && !shutting_down) {
            printf("core system service died: %s\n", srv_to_string(rp));
            _exit(1);
        }

        if (SRV_IS_UPD_SCHEDULED(rp)) {
            printf("RS: aborting the scheduled update, one of the services part of it is exiting...\n");
            abort_update_proc(EDEADSRCDST);
        }

        r = (rp->r_caller_request == RS_DOWN || (rp->r_caller_request == RS_REFRESH && norestart) ? OK : EDEADEPT);
        late_reply(rp, r);

        unpublish_service(rp);

        get_service_instances(rp, &rps, &nr_rps);
        for (i = 0; i < nr_rps; i++) {
            cleanup_service(rps[i]);
        }

        if (rp->r_flags & RS_REINCARNATE) {
            rp->r_flags &= ~RS_REINCARNATE;
            reincarnate_service(rp);
        }
    } else if (rp->r_flags & RS_REFRESHING) {
        restart_service(rp);
    } else {
        if (rp->r_restarts > 0) {
            if (!(rpub->sys_flags & SF_NO_BIN_EXP)) {
                rp->r_backoff = 1 << MIN(rp->r_restarts, (BACKOFF_BITS - 2));
                rp->r_backoff = MIN(rp->r_backoff, MAX_BACKOFF);
                if ((rpub->sys_flags & SF_USE_COPY) && rp->r_backoff > 1) rp->r_backoff = 1;
            } else {
                rp->r_backoff = 1;
            }
            return;
        }

        restart_service(rp);
    }
}

static int run_script(struct rproc *rp) {
    int r, endpoint;
    pid_t pid;
    char *reason;
    char incarnation_str[20];
    char *envp[1] = {NULL};
    struct rprocpub *rpub = rp->r_pub;
    if (rp->r_flags & RS_REFRESHING) reason = "restart";
    else if (rp->r_flags & RS_NOPINGREPLY) reason = "no-heartbeat";
    else reason = "terminated";
    snprintf(incarnation_str, sizeof(incarnation_str), "%d", rp->r_restarts);

    if (rs_verbose) {
        printf("RS: %s:\n", srv_to_string(rp));
        printf("RS:     calling script '%s'\n", rp->r_script);
        printf("RS:     reason: '%s'\n", reason);
        printf("RS:     incarnation: '%s'\n", incarnation_str);
    }

    pid = fork();
    switch (pid) {
        case -1: return errno;
        case 0:
            execle(_PATH_BSHELL, "sh", rp->r_script, rpub->label, reason,
                   incarnation_str, NULL, envp);
            printf("RS: run_script: execl '%s' failed: %s\n",
                   rp->r_script, strerror(errno));
            exit(1);
        default:
            if ((r = getprocnr(pid, &endpoint)) != 0)
                panic("unable to get child endpoint: %d", r);

            if ((r = sys_privctl(endpoint, SYS_PRIV_SET_USER, NULL)) != OK) {
                return kill_service(rp, "can't set script privileges", r);
            }

            if ((r = vm_set_priv(endpoint, NULL, FALSE)) != OK) {
                return kill_service(rp, "can't set script VM privs", r);
            }

            if ((r = sys_privctl(endpoint, SYS_PRIV_ALLOW, NULL)) != OK) {
                return kill_service(rp, "can't let the script run", r);
            }

            vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
    }

    return OK;
}

void restart_service(struct rproc *rp) {
    struct rproc *replica_rp;
    int r;

    late_reply(rp, OK);

    if (rp->r_script[0] != '\0') {
        r = run_script(rp);
        if (r != OK) {
            kill_service(rp, "unable to run script", errno);
        }
        return;
    }

    if (rp->r_next_rp == NULL) {
        r = clone_service(rp, RST_SYS_PROC, 0);
        if (r != OK) {
            kill_service(rp, "unable to clone service", r);
            return;
        }
    }

    replica_rp = rp->r_next_rp;
    r = update_service(&rp, &replica_rp, RS_SWAP, 0);
    if (r != OK) {
        kill_service(rp, "unable to update into new replica", r);
        return;
    }
    r = run_service(replica_rp, SEF_INIT_RESTART, 0);
    if (r != OK) kill_service(rp, "unable to let the replica run", r);

    if ((rp->r_pub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART))
        rp->r_flags |= RS_CLEANUP_DETACH;

    if (rs_verbose) printf("RS: %s restarted into %s\n", srv_to_string(rp), srv_to_string(replica_rp));
}

void inherit_service_defaults(struct rproc *def_rp, struct rproc *rp) {
    struct rprocpub *def_rpub = def_rp->r_pub, *rpub = rp->r_pub;

    rpub->dev_nr = def_rpub->dev_nr;
    rpub->nr_domain = def_rpub->nr_domain;
    for (int i = 0; i < def_rpub->nr_domain; i++)
        rpub->domain[i] = def_rpub->domain[i];
    rpub->pci_acl = def_rpub->pci_acl;

    rpub->sys_flags &= ~IMM_SF;
    rpub->sys_flags |= (def_rpub->sys_flags & IMM_SF);
    rp->r_priv.s_flags &= ~IMM_F;
    rp->r_priv.s_flags |= (def_rp->r_priv.s_flags & IMM_F);

    rp->r_priv.s_trap_mask = def_rp->r_priv.s_trap_mask;
}

void get_service_instances(struct rproc *rp, struct rproc ***rps, int *length) {
    static struct rproc *instances[5];
    int nr_instances = 0;

    instances[nr_instances++] = rp;
    if (rp->r_prev_rp) instances[nr_instances++] = rp->r_prev_rp;
    if (rp->r_next_rp) instances[nr_instances++] = rp->r_next_rp;
    if (rp->r_old_rp) instances[nr_instances++] = rp->r_old_rp;
    if (rp->r_new_rp) instances[nr_instances++] = rp->r_new_rp;

    *rps = instances;
    *length = nr_instances;
}

void share_exec(struct rproc *rp_dst, struct rproc *rp_src) {
    if (rs_verbose)
        printf("RS: %s shares exec image with %s\n", srv_to_string(rp_dst), srv_to_string(rp_src));
    rp_dst->r_exec_len = rp_src->r_exec_len;
    rp_dst->r_exec = rp_src->r_exec;
}

int read_exec(struct rproc *rp) {
    char *e_name = rp->r_argv[0];
    if (rs_verbose)
        printf("RS: service '%s' reads exec image from: %s\n", rp->r_pub->label, e_name);

    struct stat sb;
    if (stat(e_name, &sb) != 0) return -errno;
    if (sb.st_size < sizeof(Elf_Ehdr)) return ENOEXEC;

    int fd = open(e_name, O_RDONLY);
    if (fd == -1) return -errno;

    rp->r_exec = malloc((rp->r_exec_len = sb.st_size));
    if (!rp->r_exec) {
        printf("RS: read_exec: unable to allocate %zu bytes\n", rp->r_exec_len);
        close(fd);
        return ENOMEM;
    }

    int r = read(fd, rp->r_exec, rp->r_exec_len);
    if (r != rp->r_exec_len) {
        printf("RS: read_exec: read failed %d, errno %d\n", r, errno);
        free_exec(rp);
        return (r >= 0) ? EIO : errno;
    }

    close(fd);
    return OK;
}

void free_exec(struct rproc *rp) {
    if (rs_verbose)
        printf("RS: %s frees exec image\n", srv_to_string(rp));

    int has_shared_exec = 0;
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *other_rp = &rproc[slot_nr];
        if ((other_rp->r_flags & RS_IN_USE) && other_rp != rp && other_rp->r_exec == rp->r_exec) {
            has_shared_exec = 1;
            break;
        }
    }

    if (!has_shared_exec) free(rp->r_exec);
    rp->r_exec = NULL;
    rp->r_exec_len = 0;
}

int edit_slot(struct rproc *rp, struct rs_start *rs_start, endpoint_t source) {
    int s, i;
    struct rprocpub *rpub = rp->r_pub;

    if (rs_start->rss_ipclen == 0 || rs_start->rss_ipclen + 1 > sizeof(rp->r_ipc_list)) return EINVAL;
    s = sys_datacopy(source, (vir_bytes) rs_start->rss_ipc, SELF, (vir_bytes) rp->r_ipc_list, rs_start->rss_ipclen);
    if (s != OK) return s;
    rp->r_ipc_list[rs_start->rss_ipclen] = '\0';

    if ((rs_start->rss_nr_irq = CHECK_THRESHOLD(rs_start->rss_nr_irq, NR_IRQ))) return EINVAL;

    copy_irq_ios_for_slot(rp, rs_start);

    s = copy_label_for_slot(source, rs_start, rp);
    if (s != OK) return s;

    return realloc_execl_stmt(rp, rs_start, source);
}

int init_slot(struct rproc *rp, struct rs_start *rs_start, endpoint_t source) {
    memset(rp, 0, sizeof(*rp));
    struct rprocpub *rpub = rp->r_pub;
    memset(rpub, 0, sizeof(*rpub));

    rpub->sys_flags = DSRV_SF;
    rp->r_priv.s_flags = DSRV_F;
    rp->r_priv.s_init_flags = DSRV_I;
    rp->r_priv.s_trap_mask = DSRV_T;

    rpub->dev_nr = rs_start->rss_major;
    rpub->nr_domain = rs_start->rss_nr_domain;
    for (int i = 0; i < rs_start->rss_nr_domain; i++) rpub->domain[i] = rs_start->rss_domain[i];

    rpub->pci_acl.rsp_nr_device = rs_start->rss_nr_pci_id;
    for (int i = 0; i < rs_start->rss_nr_pci_id; i++) {
        rpub->pci_acl.rsp_device[i].vid = rs_start->rss_pci_id[i].vid;
        rpub->pci_acl.rsp_device[i].did = rs_start->rss_pci_id[i].did;
    }

    rpub->pci_acl.rsp_nr_class = rs_start->rss_nr_pci_class;
    for (int i = 0; i < rs_start->rss_nr_pci_class; i++) {
        rpub->pci_acl.rsp_class[i].pciclass = rs_start->rss_pci_class[i].pciclass;
        rpub->pci_acl.rsp_class[i].mask = rs_start->rss_pci_class[i].mask;
    }

    return edit_slot(rp, rs_start, source);
}

int clone_slot(struct rproc *rp, struct rproc **clone_rpp) {
    int r;
    struct rproc *clone_rp;
    struct rprocpub *rpub = rp->r_pub, *clone_rpub;

    if ((r = alloc_slot(&clone_rp)) != OK) {
        printf("RS: clone_slot: unable to allocate a new slot: %d\n", r);
        return r;
    }

    clone_rpub = clone_rp->r_pub;
    r = sys_getpriv(&(rp->r_priv), rpub->endpoint);

    *clone_rp = *rp;
    *clone_rpub = *rpub;

    clone_rp->r_init_err = ERESTART;
    clone_rp->r_flags &= ~RS_ACTIVE;
    clone_rp->r_pid = -1;
    clone_rpub->endpoint = -1;
    clone_rp->r_pub = clone_rpub;
    build_cmd_dep(clone_rp);
    if (clone_rpub->sys_flags & SF_USE_COPY) {
        share_exec(clone_rp, rp);
    }
    clone_rp->r_old_rp = NULL;
    clone_rp->r_new_rp = NULL;
    clone_rp->r_prev_rp = NULL;
    clone_rp->r_next_rp = NULL;
    clone_rp->r_priv.s_flags |= DYN_PRIV_ID;
    clone_rp->r_priv.s_flags &= ~(LU_SYS_PROC | RST_SYS_PROC);
    clone_rp->r_priv.s_init_flags = 0;

    *clone_rpp = clone_rp;
    return OK;
}

static void swap_slot_pointer(struct rproc **rpp, struct rproc *src_rp, struct rproc *dst_rp) {
    if (*rpp == src_rp) *rpp = dst_rp;
    else if (*rpp == dst_rp) *rpp = src_rp;
}

void swap_slot(struct rproc **src_rpp, struct rproc **dst_rpp) {
    struct rproc *src_rp = *src_rpp, *dst_rp = *dst_rpp;
    struct rprocpub *src_rpub = src_rp->r_pub, *dst_rpub = dst_rp->r_pub;
    struct rproc orig_src_rproc = *src_rp, orig_dst_rproc = *dst_rp;
    struct rprocpub orig_src_rprocpub = *src_rpub, orig_dst_rprocpub = *dst_rpub;
    struct rprocupd *prev_rpupd, *rpupd;

    *src_rp = orig_dst_rproc;
    *src_rpub = orig_dst_rprocpub;
    *dst_rp = orig_src_rproc;
    *dst_rpub = orig_src_rprocpub;

    src_rp->r_pub = orig_src_rproc.r_pub;
    dst_rp->r_pub = orig_dst_rproc.r_pub;
    build_cmd_dep(src_rp);
    build_cmd_dep(dst_rp);

    swap_slot_pointer(&src_rp->r_prev_rp, src_rp, dst_rp);
    swap_slot_pointer(&src_rp->r_next_rp, src_rp, dst_rp);
    swap_slot_pointer(&src_rp->r_old_rp, src_rp, dst_rp);
    swap_slot_pointer(&src_rp->r_new_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_prev_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_next_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_old_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_new_rp, src_rp, dst_rp);

    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd, swap_slot_pointer(&rpupd->rp, src_rp, dst_rp));
    swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)], src_rp, dst_rp);
    swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)], src_rp, dst_rp);

    *src_rpp = dst_rp;
    *dst_rpp = src_rp;
}

struct rproc* lookup_slot_by_label(char *label) {
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_ACTIVE) && strcmp(rp->r_pub->label, label) == 0) return rp;
    }
    return NULL;
}

struct rproc* lookup_slot_by_pid(pid_t pid) {
    if (pid < 0) return NULL;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && rp->r_pid == pid) return rp;
    }
    return NULL;
}

struct rproc* lookup_slot_by_dev_nr(dev_t dev_nr) {
    if (dev_nr <= 0) return NULL;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && rp->r_pub->dev_nr == dev_nr) return rp;
    }
    return NULL;
}

struct rproc* lookup_slot_by_domain(int domain) {
    if (domain <= 0) return NULL;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && (contains_domain(rp->r_pub->domain, rp->r_pub->nr_domain, domain))) return rp;
    }
    return NULL;
}

struct rproc* lookup_slot_by_flags(int flags) {
    if (!flags) return NULL;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && (rp->r_flags & flags)) return rp;
    }
    return NULL;
}

int alloc_slot(struct rproc **rpp) {
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        *rpp = &rproc[slot_nr];
        if (!((*rpp)->r_flags & RS_IN_USE)) return OK;
    }
    return ENOMEM;
}

void free_slot(struct rproc *rp) {
    late_reply(rp, OK);

    if (rp->r_pub->sys_flags & SF_USE_COPY) free_exec(rp);

    rp->r_flags = 0;
    rp->r_pid = -1;
    rp->r_pub->in_use = FALSE;
    rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = NULL;
}