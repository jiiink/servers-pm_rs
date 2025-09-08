/* This file handles the process manager's part of debugging, using the
 * ptrace system call. Most of the commands are passed on to the system
 * task for completion.
 *
 * The debugging commands available are:
 * T_STOP	stop the process
 * T_OK		enable tracing by parent for this process
 * T_GETINS	return value from instruction space
 * T_GETDATA	return value from data space
 * T_GETUSER	return value from user process table
 * T_SETINS	set value in instruction space
 * T_SETDATA	set value in data space
 * T_SETUSER	set value in user process table
 * T_RESUME	resume execution
 * T_EXIT	exit
 * T_STEP	set trace bit
 * T_SYSCALL	trace system call
 * T_ATTACH	attach to an existing process
 * T_DETACH	detach from a traced process
 * T_SETOPT	set trace options
 * T_GETRANGE	get range of values
 * T_SETRANGE	set range of values
 *
 * The T_OK, T_ATTACH, T_EXIT, and T_SETOPT commands are handled here, and the
 * T_RESUME, T_STEP, T_SYSCALL, and T_DETACH commands are partially handled
 * here and completed by the system task. The rest are handled entirely by the
 * system task.
 */

#include "pm.h"
#include <minix/com.h>
#include <minix/callnr.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include "mproc.h"

static int ptrace_do_attach(void);
static int ptrace_do_ok(void);
static int ptrace_do_read_write_byte_ins(int req);
static int ptrace_handle_tracer_command(struct mproc *child, int req);
static int ptrace_do_exit(struct mproc *child);
static int ptrace_do_set_options(struct mproc *child);
static int ptrace_do_get_set_range(struct mproc *child, int req);
static int ptrace_do_detach(struct mproc *child);
static int ptrace_do_resume_step_syscall(struct mproc *child, int req);

/*===========================================================================*
 *				do_trace  				     *
 *===========================================================================*/
int
do_trace(void)
{
  register struct mproc *child;
  int req = m_in.m_lc_pm_ptrace.req;

  switch (req) {
  case T_OK:		/* enable tracing by parent for this proc */
	return ptrace_do_ok();

  case T_ATTACH:	/* attach to an existing process */
	return ptrace_do_attach();

  case T_STOP:		/* stop the process */
	/* This call is not exposed to user programs, because its effect can be
	 * achieved better by sending the traced process a signal with kill(2).
	 */
	return(EINVAL);

  case T_READB_INS:	/* special hack for reading text segments */
  case T_WRITEB_INS:	/* special hack for patching text segments */
    return ptrace_do_read_write_byte_ins(req);

  default:
	/* All other calls are made by the tracing process to control execution
	 * of the child. For all these calls, the child must be stopped and already traced.
	 */
	if ((child = find_proc(m_in.m_lc_pm_ptrace.pid)) == NULL) return(ESRCH);
	if (child->mp_flags & EXITING) return(ESRCH);
	if (child->mp_tracer != who_p) return(ESRCH);
	if (!(child->mp_flags & TRACE_STOPPED)) return(EBUSY);

    return ptrace_handle_tracer_command(child, req);
  }
}

/*===========================================================================*
 *				ptrace_do_ok				     *
 *===========================================================================*/
static int ptrace_do_ok(void)
{
    if (mp->mp_tracer != NO_TRACER) return(EBUSY);

    mp->mp_tracer = who_p; /* Parent is now the tracer (who_p is parent, mp is child) */
    mp->mp_reply.m_pm_lc_ptrace.data = 0;
    return(OK);
}

/*===========================================================================*
 *				ptrace_do_attach			     *
 *===========================================================================*/
static int ptrace_do_attach(void)
{
    register struct mproc *child_to_trace;
    int r;

    if ((child_to_trace = find_proc(m_in.m_lc_pm_ptrace.pid)) == NULL) return(ESRCH);
    if (child_to_trace->mp_flags & EXITING) return(ESRCH);

    /* For non-root processes, user and group ID must match. */
    if (mp->mp_effuid != SUPER_USER &&
        (mp->mp_effuid != child_to_trace->mp_effuid ||
         mp->mp_effgid != child_to_trace->mp_effgid ||
         child_to_trace->mp_effuid != child_to_trace->mp_realuid ||
         child_to_trace->mp_effgid != child_to_trace->mp_realgid)) return(EPERM);

    /* Only root may trace system servers. */
    if (mp->mp_effuid != SUPER_USER && (child_to_trace->mp_flags & PRIV_PROC))
        return(EPERM);

    /* System servers may not trace anyone. They can use sys_trace(). */
    if (mp->mp_flags & PRIV_PROC) return(EPERM);

    /* Can't trace self, PM or VM. */
    if (child_to_trace == mp || child_to_trace->mp_endpoint == PM_PROC_NR ||
        child_to_trace->mp_endpoint == VM_PROC_NR) return(EPERM);

    /* Can't trace a process that is already being traced. */
    if (child_to_trace->mp_tracer != NO_TRACER) return(EBUSY);

    child_to_trace->mp_tracer = who_p; /* Current process (mp) is the tracer */
    child_to_trace->mp_trace_flags = TO_NOEXEC; /* Don't auto-trap on exec */

    /* Stop the child and send SIGSTOP to notify the tracer. */
    sig_proc(child_to_trace, SIGSTOP, TRUE /*trace*/, FALSE /* ksig */);

    mp->mp_reply.m_pm_lc_ptrace.data = 0;
    return(OK);
}

/*===========================================================================*
 *				ptrace_do_read_write_byte_ins			     *
 *===========================================================================*/
static int ptrace_do_read_write_byte_ins(int req)
{
    register struct mproc *child_target;
    int r;

    /* These are special privileged hacks, only root can use them. */
    if (mp->mp_effuid != SUPER_USER) return(EPERM);
    if ((child_target = find_proc(m_in.m_lc_pm_ptrace.pid)) == NULL) return(ESRCH);
    if (child_target->mp_flags & EXITING) return(ESRCH);

#if 0
    /* Should check for shared text */
    /* Make sure the text segment is not used as a source for shared text. */
    child_target->mp_ino = 0;
    child_target->mp_dev = 0;
    child_target->mp_ctime = 0;
#endif

    r = sys_trace(req, child_target->mp_endpoint, m_in.m_lc_pm_ptrace.addr,
        (long *)&m_in.m_lc_pm_ptrace.data); /* Cast to (long *) for data */
    if (r != OK) return(r);

    mp->mp_reply.m_pm_lc_ptrace.data = m_in.m_lc_pm_ptrace.data;
    return(OK);
}

/*===========================================================================*
 *				ptrace_handle_tracer_command			     *
 *===========================================================================*/
static int ptrace_handle_tracer_command(struct mproc *child, int req)
{
    switch (req) {
    case T_EXIT:		/* exit traced process */
        return ptrace_do_exit(child);

    case T_SETOPT:	/* set trace options */
        return ptrace_do_set_options(child);

    case T_GETRANGE:
    case T_SETRANGE:	/* get/set range of values */
        return ptrace_do_get_set_range(child, req);

    case T_DETACH:	/* detach from traced process */
        return ptrace_do_detach(child);

    case T_RESUME:
    case T_STEP:
    case T_SYSCALL:	/* resume execution */
        return ptrace_do_resume_step_syscall(child, req);

    default:
        /* For other sys_trace calls, pass through to kernel */
        int r = sys_trace(req, child->mp_endpoint, m_in.m_lc_pm_ptrace.addr,
            (long *)&m_in.m_lc_pm_ptrace.data);
        if (r != OK) return(r);
        mp->mp_reply.m_pm_lc_ptrace.data = m_in.m_lc_pm_ptrace.data;
        return OK;
    }
}

/*===========================================================================*
 *				ptrace_do_exit				     *
 *===========================================================================*/
static int ptrace_do_exit(struct mproc *child)
{
    child->mp_flags |= TRACE_EXIT; /* Mark process for forced exit by tracer */

    /* Defer the exit if the traced process has a VFS or event call pending. */
    if (child->mp_flags & (VFS_CALL | EVENT_CALL))
        child->mp_exitstatus = (char)m_in.m_lc_pm_ptrace.data; /* Save exit status */
    else
        exit_proc(child, m_in.m_lc_pm_ptrace.data, FALSE /*dump_core*/);

    /* Do not reply to the caller until VFS has processed the exit request. */
    return(SUSPEND);
}

/*===========================================================================*
 *				ptrace_do_set_options			     *
 *===========================================================================*/
static int ptrace_do_set_options(struct mproc *child)
{
    child->mp_trace_flags = m_in.m_lc_pm_ptrace.data; /* Set trace options */
    mp->mp_reply.m_pm_lc_ptrace.data = 0;
    return(OK);
}

/*===========================================================================*
 *				ptrace_do_get_set_range			     *
 *===========================================================================*/
static int ptrace_do_get_set_range(struct mproc *child, int req)
{
    struct ptrace_range pr;
    int r;

    /* Copy ptrace_range structure from user space to PM. */
    r = sys_datacopy(who_e, m_in.m_lc_pm_ptrace.addr, SELF, (vir_bytes)&pr,
        (phys_bytes)sizeof(pr));
    if (r != OK) return(r);

    if (pr.pr_space != TS_INS && pr.pr_space != TS_DATA) return(EINVAL);
    if (pr.pr_size == 0 || pr.pr_size > LONG_MAX) return(EINVAL); /* Max transfer size */

    if (req == T_GETRANGE)
        r = sys_vircopy(child->mp_endpoint, (vir_bytes) pr.pr_addr,
            who_e, (vir_bytes) pr.pr_ptr, (phys_bytes) pr.pr_size, 0);
    else /* T_SETRANGE */
        r = sys_vircopy(who_e, (vir_bytes) pr.pr_ptr,
            child->mp_endpoint, (vir_bytes) pr.pr_addr, (phys_bytes) pr.pr_size, 0);

    if (r != OK) return(r);

    mp->mp_reply.m_pm_lc_ptrace.data = 0;
    return(OK);
}

/*===========================================================================*
 *				ptrace_do_detach			     *
 *===========================================================================*/
static int ptrace_do_detach(struct mproc *child)
{
    int i, signo_to_send;

    signo_to_send = m_in.m_lc_pm_ptrace.data;
    if (signo_to_send < 0 || signo_to_send >= _NSIG)
        return(EINVAL);

    child->mp_tracer = NO_TRACER; /* Detach tracer */

    /* Let all tracer-pending signals through the filter. */
    for (i = 1; i < _NSIG; i++) {
        if (sigismember(&child->mp_sigtrace, i)) {
            sigdelset(&child->mp_sigtrace, i);
            check_sig(child->mp_pid, i, FALSE /* ksig */);
        }
    }

    if (signo_to_send > 0) { /* Issue a signal if requested */
        sig_proc(child, signo_to_send, TRUE /*trace*/, FALSE /* ksig */);
    }

    /* Resume the child as if nothing ever happened. */
    child->mp_flags &= ~TRACE_STOPPED;
    child->mp_trace_flags = 0;

    check_pending(child); /* Check for any other pending signals */

    /* The sys_trace(T_DETACH) call is needed to fully detach in kernel. */
    return sys_trace(T_DETACH, child->mp_endpoint, 0L, (long *) &mp->mp_reply.m_pm_lc_ptrace.data);
}

/*===========================================================================*
 *				ptrace_do_resume_step_syscall			     *
 *===========================================================================*/
static int ptrace_do_resume_step_syscall(struct mproc *child, int req)
{
    int i, signo_to_send;

    signo_to_send = m_in.m_lc_pm_ptrace.data;
    if (signo_to_send < 0 || signo_to_send >= _NSIG)
        return(EINVAL);

    if (signo_to_send > 0) { /* Issue a signal if requested */
        sig_proc(child, signo_to_send, FALSE /*trace*/, FALSE /* ksig */);
    }

    /* If there are any other signals waiting to be delivered to the tracer,
     * feign a successful resumption (the child will remain stopped and tracer
     * will be notified). */
    for (i = 1; i < _NSIG; i++) {
        if (sigismember(&child->mp_sigtrace, i)) {
            mp->mp_reply.m_pm_lc_ptrace.data = 0;
            return(OK);
        }
    }

    child->mp_flags &= ~TRACE_STOPPED; /* Mark child as no longer stopped for tracing */

    check_pending(child); /* Check for any pending signals directly for the child */

    /* Finally, issue the resume command to the kernel. */
    return sys_trace(req, child->mp_endpoint, m_in.m_lc_pm_ptrace.addr,
        (long *)&mp->mp_reply.m_pm_lc_ptrace.data);
}


/*===========================================================================*
 *				trace_stop				     *
 *===========================================================================*/
void
trace_stop(register struct mproc *rmp_child, int signo)
{
/* A traced process got a signal so stop it. */

  register struct mproc *rpmp_tracer = mproc + rmp_child->mp_tracer;
  int r;

  r = sys_trace(T_STOP, rmp_child->mp_endpoint, 0L, (long *) NULL);
  if (r != OK) panic("sys_trace failed to stop endpoint %d: %d", rmp_child->mp_endpoint, r);

  rmp_child->mp_flags |= TRACE_STOPPED;
  if (wait_test(rpmp_tracer, rmp_child)) {
	/* TODO: rusage support */

	sigdelset(&rmp_child->mp_sigtrace, signo); /* Remove this signal from tracer pending */

	rpmp_tracer->mp_flags &= ~WAITING;	/* tracer is no longer waiting */
	rpmp_tracer->mp_reply.m_pm_lc_wait4.status = W_STOPCODE(signo);
	reply(rmp_child->mp_tracer, rmp_child->mp_pid);
  }
}