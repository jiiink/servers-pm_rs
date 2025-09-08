#include "pm.h"
#include <minix/com.h>
#include <minix/callnr.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include "mproc.h"

static int trace_attach(struct ptrace_range pr);
static int handle_trace_stop(struct mproc *child);
static int attach_to_process(struct mproc *child);

int do_trace(void)
{
    int req = m_in.m_lc_pm_ptrace.req;
    struct mproc *child;

    switch (req) {
    case T_OK:
        if (mp->mp_tracer != NO_TRACER) return EBUSY;
        mp->mp_tracer = mp->mp_parent;
        mp->mp_reply.m_pm_lc_ptrace.data = 0;
        return OK;

    case T_ATTACH:
        child = find_proc(m_in.m_lc_pm_ptrace.pid);
        if (!child || (child->mp_flags & EXITING)) return ESRCH;
        if (attach_to_process(child) != OK) return EPERM;
        return OK;

    case T_STOP:
        return EINVAL;

    case T_READB_INS:
    case T_WRITEB_INS:
        if (handle_trace_stop(find_proc(m_in.m_lc_pm_ptrace.pid)) != OK) return ESRCH;
        break;

    case T_EXIT:
    case T_SETOPT:
    case T_GETRANGE:
    case T_SETRANGE:
    case T_DETACH:
    case T_RESUME:
    case T_STEP:
    case T_SYSCALL:
        child = find_proc(m_in.m_lc_pm_ptrace.pid);
        if (!child || (child->mp_flags & EXITING) || child->mp_tracer != who_p || !(child->mp_flags & TRACE_STOPPED))
            return handle_trace_stop(child);
        break;

    default:
        return EINVAL;
    }

    int r = sys_trace(req, child->mp_endpoint, m_in.m_lc_pm_ptrace.addr, &m_in.m_lc_pm_ptrace.data);
    if (r != OK) return r;

    mp->mp_reply.m_pm_lc_ptrace.data = m_in.m_lc_pm_ptrace.data;
    return OK;
}

static int trace_attach(struct ptrace_range pr)
{
    if (pr.pr_space != TS_INS && pr.pr_space != TS_DATA) return EINVAL;
    if (pr.pr_size == 0 || pr.pr_size > LONG_MAX) return EINVAL;

    return OK;
}

static int handle_trace_stop(struct mproc *child)
{
    if (!child || (child->mp_flags & EXITING)) return ESRCH;
    int r = sys_trace(req, child->mp_endpoint, m_in.m_lc_pm_ptrace.addr, &m_in.m_lc_pm_ptrace.data);
    if (r != OK) return r;
    mp->mp_reply.m_pm_lc_ptrace.data = m_in.m_lc_pm_ptrace.data;
    return OK;
}

static int attach_to_process(struct mproc *child)
{
    if (mp->mp_effuid != SUPER_USER &&
        (mp->mp_effuid != child->mp_effuid ||
         mp->mp_effgid != child->mp_effgid ||
         child->mp_effuid != child->mp_realuid ||
         child->mp_effgid != child->mp_realgid)) return EPERM;

    if (mp->mp_effuid != SUPER_USER && (child->mp_flags & PRIV_PROC)) return EPERM;
    if (mp->mp_flags & PRIV_PROC) return EPERM;
    if (child == mp || child->mp_endpoint == PM_PROC_NR || child->mp_endpoint == VM_PROC_NR) return EPERM;
    if (child->mp_tracer != NO_TRACER) return EBUSY;

    child->mp_tracer = who_p;
    child->mp_trace_flags = TO_NOEXEC;
    sig_proc(child, SIGSTOP, TRUE, FALSE);
    mp->mp_reply.m_pm_lc_ptrace.data = 0;
    return OK;
}

void trace_stop(struct mproc *rmp, int signo)
{
    struct mproc *rpmp = mproc + rmp->mp_tracer;
    int r = sys_trace(T_STOP, rmp->mp_endpoint, 0L, (long *)0);
    if (r != OK) panic("sys_trace failed: %d", r);

    rmp->mp_flags |= TRACE_STOPPED;
    if (wait_test(rpmp, rmp)) {
        sigdelset(&rmp->mp_sigtrace, signo);
        rpmp->mp_flags &= ~WAITING;
        rpmp->mp_reply.m_pm_lc_wait4.status = W_STOPCODE(signo);
        reply(rmp->mp_tracer, rmp->mp_pid);
    }
}