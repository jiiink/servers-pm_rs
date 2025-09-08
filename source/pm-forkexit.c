#include "pm.h"
#include <sys/wait.h>
#include <assert.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/sched.h>
#include <minix/vm.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <signal.h>
#include "mproc.h"

#define LAST_FEW 2

static void zombify(struct mproc *rmp);
static void check_parent(struct mproc *child);
static int tell_parent(struct mproc *child, vir_bytes addr);
static void tell_tracer(struct mproc *child);
static void tracer_died(struct mproc *child);
static void cleanup(struct mproc *rmp);
static int allocate_child_slot(void);

int do_fork(void) {
    register struct mproc *rmp = mp, *rmc;
    endpoint_t child_ep;
    pid_t new_pid;
    static unsigned int next_child = 0;
    message m;
    int s;

    if (procs_in_use == NR_PROCS || (procs_in_use >= NR_PROCS - LAST_FEW && rmp->mp_effuid != 0)) {
        printf("PM: warning, process table is full!\n");
        return EAGAIN;
    }

    int child_slot = allocate_child_slot();
    if (child_slot < 0)
        panic("do_fork can't find child slot");

    s = vm_fork(rmp->mp_endpoint, child_slot, &child_ep);
    if (s != OK) return s;

    rmc = &mproc[child_slot];
    procs_in_use++;
    *rmc = *rmp;
    rmc->mp_sigact = mpsigact[child_slot];
    memcpy(rmc->mp_sigact, rmp->mp_sigact, sizeof(mpsigact[child_slot]));
    rmc->mp_parent = who_p;
    if (!(rmc->mp_trace_flags & TO_TRACEFORK)) {
        rmc->mp_tracer = NO_TRACER;
        rmc->mp_trace_flags = 0;
        (void)sigemptyset(&rmc->mp_sigtrace);
    }
    rmc->mp_flags &= (IN_USE | DELAY_CALL | TAINTED);
    rmc->mp_child_utime = 0;
    rmc->mp_child_stime = 0;
    rmc->mp_exitstatus = 0;
    rmc->mp_sigstatus = 0;
    rmc->mp_endpoint = child_ep;
    for (int i = 0; i < NR_ITIMERS; i++)
        rmc->mp_interval[i] = 0;
    rmc->mp_started = getticks();
    assert(rmc->mp_eventsub == NO_EVENTSUB);
    new_pid = get_free_pid();
    rmc->mp_pid = new_pid;

    memset(&m, 0, sizeof(m));
    m.m_type = VFS_PM_FORK;
    m.VFS_PM_ENDPT = rmc->mp_endpoint;
    m.VFS_PM_PENDPT = rmp->mp_endpoint;
    m.VFS_PM_CPID = rmc->mp_pid;
    m.VFS_PM_REUID = -1;
    m.VFS_PM_REGID = -1;

    tell_vfs(rmc, &m);

    if (rmc->mp_tracer != NO_TRACER)
        sig_proc(rmc, SIGSTOP, 1, 0);

    return SUSPEND;
}

int do_srv_fork(void) {
    register struct mproc *rmp = mp, *rmc;
    endpoint_t child_ep;
    pid_t new_pid;
    static unsigned int next_child = 0;
    message m;
    int s;

    if (mp->mp_endpoint != RS_PROC_NR) return EPERM;

    if (procs_in_use == NR_PROCS || (procs_in_use >= NR_PROCS - LAST_FEW && rmp->mp_effuid != 0)) {
        printf("PM: warning, process table is full!\n");
        return EAGAIN;
    }

    int child_slot = allocate_child_slot();
    if (child_slot < 0) panic("do_fork can't find child slot");

    s = vm_fork(rmp->mp_endpoint, child_slot, &child_ep);
    if (s != OK) return s;

    rmc = &mproc[child_slot];
    procs_in_use++;
    *rmc = *rmp;
    rmc->mp_sigact = mpsigact[child_slot];
    memcpy(rmc->mp_sigact, rmp->mp_sigact, sizeof(mpsigact[child_slot]));
    rmc->mp_parent = who_p;
    if (!(rmc->mp_trace_flags & TO_TRACEFORK)) {
        rmc->mp_tracer = NO_TRACER;
        rmc->mp_trace_flags = 0;
        (void)sigemptyset(&rmc->mp_sigtrace);
    }
    rmc->mp_flags &= (IN_USE | PRIV_PROC | DELAY_CALL);
    rmc->mp_child_utime = 0;
    rmc->mp_child_stime = 0;
    rmc->mp_exitstatus = 0;
    rmc->mp_sigstatus = 0;
    rmc->mp_endpoint = child_ep;
    rmc->mp_realuid = m_in.m_lsys_pm_srv_fork.uid;
    rmc->mp_effuid = m_in.m_lsys_pm_srv_fork.uid;
    rmc->mp_svuid = m_in.m_lsys_pm_srv_fork.uid;
    rmc->mp_realgid = m_in.m_lsys_pm_srv_fork.gid;
    rmc->mp_effgid = m_in.m_lsys_pm_srv_fork.gid;
    rmc->mp_svgid = m_in.m_lsys_pm_srv_fork.gid;
    for (int i = 0; i < NR_ITIMERS; i++)
        rmc->mp_interval[i] = 0;
    rmc->mp_started = getticks();
    assert(rmc->mp_eventsub == NO_EVENTSUB);
    new_pid = get_free_pid();
    rmc->mp_pid = new_pid;

    memset(&m, 0, sizeof(m));
    m.m_type = VFS_PM_SRV_FORK;
    m.VFS_PM_ENDPT = rmc->mp_endpoint;
    m.VFS_PM_PENDPT = rmp->mp_endpoint;
    m.VFS_PM_CPID = rmc->mp_pid;
    m.VFS_PM_REUID = m_in.m_lsys_pm_srv_fork.uid;
    m.VFS_PM_REGID = m_in.m_lsys_pm_srv_fork.gid;

    tell_vfs(rmc, &m);

    if (rmc->mp_tracer != NO_TRACER)
        sig_proc(rmc, SIGSTOP, 1 /*trace*/, 0 /* ksig */);

    reply(rmc - mproc, OK);
    return rmc->mp_pid;
}

int do_exit(void) {
    if (mp->mp_flags & PRIV_PROC) {
        printf("PM: system process %d (%s) tries to exit(), sending SIGKILL\n", mp->mp_endpoint, mp->mp_name);
        sys_kill(mp->mp_endpoint, SIGKILL);
    } else {
        exit_proc(mp, m_in.m_lc_pm_exit.status, 0);
    }
    return SUSPEND;
}

void exit_proc(struct mproc *rmp, int exit_status, int dump_core) {
    int proc_nr_e;
    message m;

    if (dump_core && rmp->mp_realuid != rmp->mp_effuid) dump_core = 0;
    if (dump_core && (rmp->mp_flags & PRIV_PROC)) dump_core = 0;
    proc_nr_e = rmp->mp_endpoint;

    if (!(rmp->mp_flags & PROC_STOPPED)) {
        int r = sys_stop(proc_nr_e);
        if (r != OK) panic("sys_stop failed: %d", r);
        rmp->mp_flags |= PROC_STOPPED;
    }
    if (vm_willexit(proc_nr_e) != OK) panic("exit_proc: vm_willexit failed");

    if (proc_nr_e == INIT_PROC_NR) {
        printf("PM: INIT died with exit status %d; showing stacktrace\n", exit_status);
        sys_diagctl_stacktrace(proc_nr_e);
        return;
    }
    if (proc_nr_e == VFS_PROC_NR) panic("exit_proc: VFS died");

    memset(&m, 0, sizeof(m));
    m.m_type = dump_core ? VFS_PM_DUMPCORE : VFS_PM_EXIT;
    m.VFS_PM_ENDPT = rmp->mp_endpoint;

    if (dump_core) {
        m.VFS_PM_TERM_SIG = rmp->mp_sigstatus;
        m.VFS_PM_PATH = rmp->mp_name;
    }

    tell_vfs(rmp, &m);

    if (rmp->mp_flags & PRIV_PROC) {
        if (sys_clear(rmp->mp_endpoint) != OK) panic("exit_proc: sys_clear failed");
    }

    rmp->mp_flags &= (IN_USE | VFS_CALL | PRIV_PROC | TRACE_EXIT | PROC_STOPPED);
    rmp->mp_flags |= EXITING;
    rmp->mp_exitstatus = (char)exit_status;
    if (!dump_core) zombify(rmp);

    for (struct mproc *child = &mproc[0]; child < &mproc[NR_PROCS]; child++) {
        if (!(child->mp_flags & IN_USE)) continue;
        if (child->mp_tracer == rmp - mproc) tracer_died(child);
        if (child->mp_parent == rmp - mproc) {
            child->mp_parent = INIT_PROC_NR;
            if (child->mp_flags & VFS_CALL) child->mp_flags |= NEW_PARENT;
            if (child->mp_flags & ZOMBIE) check_parent(child);
        }
    }

    check_sig(-(rmp->mp_pid == mp->mp_procgrp ? mp->mp_procgrp : 0), SIGHUP, 0);
}

void exit_restart(struct mproc *rmp) {
    int r;

    if ((r = sched_stop(rmp->mp_scheduler, rmp->mp_endpoint)) != OK) {
        printf("PM: The scheduler did not want to give up scheduling %s, ret=%d.\n", rmp->mp_name, r);
    }

    rmp->mp_scheduler = NONE;

    if (!(rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE | TOLD_PARENT))) zombify(rmp);

    if (!(rmp->mp_flags & PRIV_PROC)) {
        if ((r = sys_clear(rmp->mp_endpoint)) != OK)
            panic("exit_restart: sys_clear failed: %d", r);
    }

    if ((r = vm_exit(rmp->mp_endpoint)) != OK)
        panic("exit_restart: vm_exit failed: %d", r);

    if (rmp->mp_flags & TRACE_EXIT) {
        mproc[rmp->mp_tracer].mp_reply.m_pm_lc_ptrace.data = 0;
        reply(rmp->mp_tracer, OK);
    }

    if (rmp->mp_flags & TOLD_PARENT) cleanup(rmp);
}

int do_wait4(void) {
    register struct mproc *rp;
    vir_bytes addr = m_in.m_lc_pm_wait4.addr;
    int pidarg = m_in.m_lc_pm_wait4.pid;
    int options = m_in.m_lc_pm_wait4.options;
    int children = 0;

    if (pidarg == 0) pidarg = -mp->mp_procgrp;

    for (rp = &mproc[0]; rp < &mproc[NR_PROCS]; rp++) {
        if ((rp->mp_flags & (IN_USE | TOLD_PARENT)) != IN_USE) continue;
        if (rp->mp_parent != who_p && rp->mp_tracer != who_p) continue;
        if (rp->mp_parent != who_p && (rp->mp_flags & ZOMBIE)) continue;

        if (pidarg > 0 && pidarg != rp->mp_pid) continue;
        if (pidarg < -1 && -pidarg != rp->mp_procgrp) continue;

        children++;
        
        if (rp->mp_flags & TRACE_ZOMBIE) {
            tell_tracer(rp);
            check_parent(rp);
            return SUSPEND;
        }
        if (rp->mp_flags & TRACE_STOPPED) {
            for (int i = 1; i < _NSIG; i++) {
                if (sigismember(&rp->mp_sigtrace, i)) {
                    sigdelset(&rp->mp_sigtrace, i);
                    mp->mp_reply.m_pm_lc_wait4.status = W_STOPCODE(i);
                    return rp->mp_pid;
                }
            }
        }
      
        if (rp->mp_flags & ZOMBIE) {
            int waited_for = tell_parent(rp, addr);
            if (waited_for && !(rp->mp_flags & (VFS_CALL | EVENT_CALL))) cleanup(rp);
            return SUSPEND;
        }
    }

    if (children > 0) {
        if (options & WNOHANG) return 0;
        mp->mp_flags |= WAITING;
        mp->mp_wpid = (pid_t)pidarg;
        mp->mp_waddr = addr;
        return SUSPEND;
    } else {
        return ECHILD;
    }
}

int wait_test(struct mproc *rmp, struct mproc *child) {
    pid_t pidarg = rmp->mp_wpid;
    int parent_waiting = rmp->mp_flags & WAITING;
    int right_child = (pidarg == -1 || pidarg == child->mp_pid || -pidarg == child->mp_procgrp);
    return (parent_waiting && right_child);
}

static void zombify(struct mproc *rmp) {
    if (rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE)) panic("zombify: already a zombie");

    if (rmp->mp_tracer != NO_TRACER && rmp->mp_tracer != rmp->mp_parent) {
        rmp->mp_flags |= TRACE_ZOMBIE;
        struct mproc *t_mp = &mproc[rmp->mp_tracer];
        if (!wait_test(t_mp, rmp)) return;
        tell_tracer(rmp);
    } else {
        rmp->mp_flags |= ZOMBIE;
    }

    check_parent(rmp);
}

static void check_parent(struct mproc *child) {
    struct mproc *p_mp = &mproc[child->mp_parent];

    if (p_mp->mp_flags & EXITING) return;
    if (wait_test(p_mp, child)) {
        if (!tell_parent(child, p_mp->mp_waddr)) return;
        if (!(child->mp_flags & (VFS_CALL | EVENT_CALL))) cleanup(child);
    }
    else {
        sig_proc(p_mp, SIGCHLD, 1, 0);
    }
}

static int tell_parent(struct mproc *child, vir_bytes addr) {
    struct rusage r_usage;
    int mp_parent = child->mp_parent;
    struct mproc *parent = &mproc[mp_parent];

    if (addr) {
        memset(&r_usage, 0, sizeof(r_usage));
        set_rusage_times(&r_usage, child->mp_child_utime, child->mp_child_stime);
        int r = sys_datacopy(SELF, (vir_bytes)&r_usage, parent->mp_endpoint, addr, sizeof(r_usage));
        if (r != OK) {
            reply(child->mp_parent, r);
            return 0;
        }
    }

    parent->mp_reply.m_pm_lc_wait4.status = W_EXITCODE(child->mp_exitstatus, child->mp_sigstatus);
    reply(child->mp_parent, child->mp_pid);
    parent->mp_flags &= ~WAITING;
    child->mp_flags &= ~ZOMBIE;
    child->mp_flags |= TOLD_PARENT;
    parent->mp_child_utime += child->mp_child_utime;
    parent->mp_child_stime += child->mp_child_stime;
    return 1;
}

static void tell_tracer(struct mproc *child) {
    int mp_tracer = child->mp_tracer;
    struct mproc *tracer = &mproc[mp_tracer];

    tracer->mp_reply.m_pm_lc_wait4.status = W_EXITCODE(child->mp_exitstatus, (child->mp_sigstatus & 0377));
    reply(child->mp_tracer, child->mp_pid);
    tracer->mp_flags &= ~WAITING;
    child->mp_flags &= ~TRACE_ZOMBIE;
    child->mp_flags |= ZOMBIE;
}

static void tracer_died(struct mproc *child) {
    child->mp_tracer = NO_TRACER;
    child->mp_flags &= ~TRACE_EXIT;

    if (!(child->mp_flags & EXITING)) {
        sig_proc(child, SIGKILL, 1, 0);
        return;
    }

    if (child->mp_flags & TRACE_ZOMBIE) {
        child->mp_flags &= ~TRACE_ZOMBIE;
        child->mp_flags |= ZOMBIE;
        check_parent(child);
    }
}

static void cleanup(struct mproc *rmp) {
    rmp->mp_pid = 0;
    rmp->mp_flags = 0;
    rmp->mp_child_utime = 0;
    rmp->mp_child_stime = 0;
    procs_in_use--;
}

static int allocate_child_slot(void) {
    static unsigned int next_child = 0;
    int n = 0;

    do {
        next_child = (next_child + 1) % NR_PROCS;
        n++;
    } while ((mproc[next_child].mp_flags & IN_USE) && n <= NR_PROCS);

    return n <= NR_PROCS ? next_child : -1;
}