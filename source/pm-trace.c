#include "pm.h"
#include <minix/com.h>
#include <minix/callnr.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include "mproc.h"

static int is_valid_sig(int sig)
{
  return sig >= 0 && sig < _NSIG;
}

static int get_live_child(pid_t pid, struct mproc **out)
{
  struct mproc *child = find_proc(pid);
  if (child == NULL) return ESRCH;
  if (child->mp_flags & EXITING) return ESRCH;
  *out = child;
  return OK;
}

static int handle_ins_rw(int req, pid_t pid, long addr, long *data)
{
  struct mproc *child;
  int r;

  if (mp->mp_effuid != SUPER_USER) return EPERM;

  r = get_live_child(pid, &child);
  if (r != OK) return r;

  r = sys_trace(req, child->mp_endpoint, addr, data);
  if (r != OK) return r;

  mp->mp_reply.m_pm_lc_ptrace.data = *data;
  return OK;
}

/*===========================================================================*
 *				do_trace  				     *
 *===========================================================================*/
int do_trace(void)
{
  struct mproc *child;
  struct ptrace_range pr;
  int i, r, req;

  req = m_in.m_lc_pm_ptrace.req;

  switch (req) {
  case T_OK:
	if (mp->mp_tracer != NO_TRACER) return EBUSY;

	mp->mp_tracer = mp->mp_parent;
	mp->mp_reply.m_pm_lc_ptrace.data = 0;
	return OK;

  case T_ATTACH:
	r = get_live_child(m_in.m_lc_pm_ptrace.pid, &child);
	if (r != OK) return r;

	if (mp->mp_effuid != SUPER_USER &&
		(mp->mp_effuid != child->mp_effuid ||
		 mp->mp_effgid != child->mp_effgid ||
		 child->mp_effuid != child->mp_realuid ||
		 child->mp_effgid != child->mp_realgid)) return EPERM;

	if (mp->mp_effuid != SUPER_USER && (child->mp_flags & PRIV_PROC))
		return EPERM;

	if (mp->mp_flags & PRIV_PROC) return EPERM;

	if (child == mp || child->mp_endpoint == PM_PROC_NR ||
		child->mp_endpoint == VM_PROC_NR) return EPERM;

	if (child->mp_tracer != NO_TRACER) return EBUSY;

	child->mp_tracer = who_p;
	child->mp_trace_flags = TO_NOEXEC;

	sig_proc(child, SIGSTOP, TRUE, FALSE);

	mp->mp_reply.m_pm_lc_ptrace.data = 0;
	return OK;

  case T_STOP:
	return EINVAL;

  case T_READB_INS:
	return handle_ins_rw(req, m_in.m_lc_pm_ptrace.pid,
		m_in.m_lc_pm_ptrace.addr, &m_in.m_lc_pm_ptrace.data);

  case T_WRITEB_INS:
	return handle_ins_rw(req, m_in.m_lc_pm_ptrace.pid,
		m_in.m_lc_pm_ptrace.addr, &m_in.m_lc_pm_ptrace.data);
  }

  r = get_live_child(m_in.m_lc_pm_ptrace.pid, &child);
  if (r != OK) return r;
  if (child->mp_tracer != who_p) return ESRCH;
  if (!(child->mp_flags & TRACE_STOPPED)) return EBUSY;

  switch (req) {
  case T_EXIT:
	child->mp_flags |= TRACE_EXIT;

	if (child->mp_flags & (VFS_CALL | EVENT_CALL))
		child->mp_exitstatus = m_in.m_lc_pm_ptrace.data;
	else
		exit_proc(child, m_in.m_lc_pm_ptrace.data, FALSE);

	return SUSPEND;

  case T_SETOPT:
	child->mp_trace_flags = m_in.m_lc_pm_ptrace.data;

	mp->mp_reply.m_pm_lc_ptrace.data = 0;
	return OK;

  case T_GETRANGE:
  case T_SETRANGE:
	r = sys_datacopy(who_e, m_in.m_lc_pm_ptrace.addr, SELF,
		(vir_bytes)&pr, (phys_bytes)sizeof(pr));
	if (r != OK) return r;

	if (pr.pr_space != TS_INS && pr.pr_space != TS_DATA) return EINVAL;
	if (pr.pr_size == 0 || pr.pr_size > LONG_MAX) return EINVAL;

	if (req == T_GETRANGE)
		r = sys_vircopy(child->mp_endpoint, (vir_bytes) pr.pr_addr,
			who_e, (vir_bytes) pr.pr_ptr, (phys_bytes) pr.pr_size, 0);
	else
		r = sys_vircopy(who_e, (vir_bytes) pr.pr_ptr,
			child->mp_endpoint, (vir_bytes) pr.pr_addr,
			(phys_bytes) pr.pr_size, 0);

	if (r != OK) return r;

	mp->mp_reply.m_pm_lc_ptrace.data = 0;
	return OK;

  case T_DETACH:
	if (!is_valid_sig(m_in.m_lc_pm_ptrace.data)) return EINVAL;

	child->mp_tracer = NO_TRACER;

	for (i = 1; i < _NSIG; i++) {
		if (sigismember(&child->mp_sigtrace, i)) {
			sigdelset(&child->mp_sigtrace, i);
			check_sig(child->mp_pid, i, FALSE);
		}
	}

	if (m_in.m_lc_pm_ptrace.data > 0) {
		sig_proc(child, m_in.m_lc_pm_ptrace.data, TRUE, FALSE);
	}

	child->mp_flags &= ~TRACE_STOPPED;
	child->mp_trace_flags = 0;

	check_pending(child);

	break;

  case T_RESUME:
  case T_STEP:
  case T_SYSCALL:
	if (!is_valid_sig(m_in.m_lc_pm_ptrace.data)) return EINVAL;

	if (m_in.m_lc_pm_ptrace.data > 0) {
		sig_proc(child, m_in.m_lc_pm_ptrace.data, FALSE, FALSE);
	}

	for (i = 1; i < _NSIG; i++) {
		if (sigismember(&child->mp_sigtrace, i)) {
			mp->mp_reply.m_pm_lc_ptrace.data = 0;
			return OK;
		}
	}

	child->mp_flags &= ~TRACE_STOPPED;

	check_pending(child);

	break;
  }

  r = sys_trace(req, child->mp_endpoint, m_in.m_lc_pm_ptrace.addr,
	&m_in.m_lc_pm_ptrace.data);
  if (r != OK) return r;

  mp->mp_reply.m_pm_lc_ptrace.data = m_in.m_lc_pm_ptrace.data;
  return OK;
}

/*===========================================================================*
 *				trace_stop				     *
 *===========================================================================*/
void trace_stop(struct mproc *rmp, int signo)
{
  struct mproc *tracer = mproc + rmp->mp_tracer;
  int r;

  r = sys_trace(T_STOP, rmp->mp_endpoint, 0, NULL);
  if (r != OK) panic("sys_trace failed: %d", r);

  rmp->mp_flags |= TRACE_STOPPED;
  if (wait_test(tracer, rmp)) {
	sigdelset(&rmp->mp_sigtrace, signo);

	tracer->mp_flags &= ~WAITING;
	tracer->mp_reply.m_pm_lc_wait4.status = W_STOPCODE(signo);
	reply(rmp->mp_tracer, rmp->mp_pid);
  }
}