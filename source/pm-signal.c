#include "pm.h"
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <minix/com.h>
#include <minix/vm.h>
#include <signal.h>
#include <sys/resource.h>
#include <assert.h>
#include "mproc.h"

static int unpause(struct mproc *rmp);
static int sig_send(struct mproc *rmp, int signo);
static void sig_proc_exit(struct mproc *rmp, int signo);
static void add_pending_signal(struct mproc *rmp, int signo, int ksig);
static void del_pending_signal(struct mproc *rmp, int signo);

/*===========================================================================*
 *				do_sigaction				     *
 *===========================================================================*/
int do_sigaction(void)
{
  int r, sig_nr;
  struct sigaction svec;
  struct sigaction *svp;

  assert(!(mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL)));

  sig_nr = m_in.m_lc_pm_sig.nr;
  if (sig_nr == SIGKILL) return OK;
  if (sig_nr < 1 || sig_nr >= _NSIG) return EINVAL;

  svp = &mp->mp_sigact[sig_nr];
  if (m_in.m_lc_pm_sig.oact != 0) {
	r = sys_datacopy(PM_PROC_NR, (vir_bytes) svp, who_e,
		m_in.m_lc_pm_sig.oact, (phys_bytes) sizeof(svec));
	if (r != OK) return r;
  }

  if (m_in.m_lc_pm_sig.act == 0) return OK;

  r = sys_datacopy(who_e, m_in.m_lc_pm_sig.act, PM_PROC_NR, (vir_bytes) &svec,
	  (phys_bytes) sizeof(svec));
  if (r != OK) return r;

  if (svec.sa_handler == SIG_IGN) {
	sigaddset(&mp->mp_ignore, sig_nr);
	sigdelset(&mp->mp_sigpending, sig_nr);
	sigdelset(&mp->mp_ksigpending, sig_nr);
	sigdelset(&mp->mp_catch, sig_nr);
  } else if (svec.sa_handler == SIG_DFL) {
	sigdelset(&mp->mp_ignore, sig_nr);
	sigdelset(&mp->mp_catch, sig_nr);
  } else {
	sigdelset(&mp->mp_ignore, sig_nr);
	sigaddset(&mp->mp_catch, sig_nr);
  }
  mp->mp_sigact[sig_nr].sa_handler = svec.sa_handler;
  sigdelset(&svec.sa_mask, SIGKILL);
  sigdelset(&svec.sa_mask, SIGSTOP);
  mp->mp_sigact[sig_nr].sa_mask = svec.sa_mask;
  mp->mp_sigact[sig_nr].sa_flags = svec.sa_flags;
  mp->mp_sigreturn = m_in.m_lc_pm_sig.ret;
  return OK;
}

/*===========================================================================*
 *				do_sigpending                                *
 *===========================================================================*/
int do_sigpending(void)
{
  assert(!(mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL)));

  mp->mp_reply.m_pm_lc_sigset.set = mp->mp_sigpending;
  return OK;
}

/*===========================================================================*
 *				do_sigprocmask                               *
 *===========================================================================*/
int do_sigprocmask(void)
{
  sigset_t set;
  int i;

  assert(!(mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL)));

  set = m_in.m_lc_pm_sigset.set;
  mp->mp_reply.m_pm_lc_sigset.set = mp->mp_sigmask;

  switch (m_in.m_lc_pm_sigset.how) {
      case SIG_BLOCK:
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	for (i = 1; i < _NSIG; i++) {
		if (sigismember(&set, i)) sigaddset(&mp->mp_sigmask, i);
	}
	break;

      case SIG_UNBLOCK:
	for (i = 1; i < _NSIG; i++) {
		if (sigismember(&set, i)) sigdelset(&mp->mp_sigmask, i);
	}
	check_pending(mp);
	break;

      case SIG_SETMASK:
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	mp->mp_sigmask = set;
	check_pending(mp);
	break;

      case SIG_INQUIRE:
	break;

      default:
	return EINVAL;
  }
  return OK;
}

/*===========================================================================*
 *				do_sigsuspend                                *
 *===========================================================================*/
int do_sigsuspend(void)
{
  assert(!(mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL)));

  mp->mp_sigmask2 = mp->mp_sigmask;
  mp->mp_sigmask = m_in.m_lc_pm_sigset.set;
  sigdelset(&mp->mp_sigmask, SIGKILL);
  sigdelset(&mp->mp_sigmask, SIGSTOP);
  mp->mp_flags |= SIGSUSPENDED;
  check_pending(mp);
  return SUSPEND;
}

/*===========================================================================*
 *				do_sigreturn				     *
 *===========================================================================*/
int do_sigreturn(void)
{
  int r;

  assert(!(mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL)));

  mp->mp_sigmask = m_in.m_lc_pm_sigset.set;
  sigdelset(&mp->mp_sigmask, SIGKILL);
  sigdelset(&mp->mp_sigmask, SIGSTOP);

  r = sys_sigreturn(who_e, (struct sigmsg *) m_in.m_lc_pm_sigset.ctx);
  check_pending(mp);
  return r;
}

/*===========================================================================*
 *				do_kill					     *
 *===========================================================================*/
int do_kill(void)
{
  return check_sig(m_in.m_lc_pm_sig.pid, m_in.m_lc_pm_sig.nr, FALSE);
}

/*===========================================================================*
 *			      do_srv_kill				     *
 *===========================================================================*/
int do_srv_kill(void)
{
  if (mp->mp_endpoint != RS_PROC_NR) return EPERM;

  return check_sig(m_in.m_rs_pm_srv_kill.pid, m_in.m_rs_pm_srv_kill.nr, TRUE);
}

/*===========================================================================*
 *				stop_proc				     *
 *===========================================================================*/
static int stop_proc(struct mproc *rmp, int may_delay)
{
  int r;

  assert(!(rmp->mp_flags & (PROC_STOPPED | DELAY_CALL | UNPAUSED)));

  r = sys_delay_stop(rmp->mp_endpoint);

  switch (r) {
  case OK:
	rmp->mp_flags |= PROC_STOPPED;
	return TRUE;
  case EBUSY:
	if (!may_delay) panic("stop_proc: unexpected delay call");
	rmp->mp_flags |= DELAY_CALL;
	return FALSE;
  default:
	panic("sys_delay_stop failed: %d", r);
  }
}

/*===========================================================================*
 *				try_resume_proc				     *
 *===========================================================================*/
static void try_resume_proc(struct mproc *rmp)
{
  int r;

  assert(rmp->mp_flags & PROC_STOPPED);

  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL | EXITING)) return;

  r = sys_resume(rmp->mp_endpoint);
  if (r != OK) panic("sys_resume failed: %d", r);

  rmp->mp_flags &= ~(PROC_STOPPED | UNPAUSED);
}

/*===========================================================================*
 *				process_ksig				     *
 *===========================================================================*/
int process_ksig(endpoint_t proc_nr_e, int signo)
{
  struct mproc *rmp;
  int proc_nr;
  pid_t proc_id, target_id;

  if (pm_isokendpt(proc_nr_e, &proc_nr) != OK) return EDEADEPT;
  rmp = &mproc[proc_nr];
  if ((rmp->mp_flags & (IN_USE | EXITING)) != IN_USE) return EDEADEPT;

  proc_id = rmp->mp_pid;
  mp = &mproc[0];
  mp->mp_procgrp = rmp->mp_procgrp;

  switch (signo) {
      case SIGINT:
      case SIGQUIT:
      case SIGWINCH:
      case SIGINFO:
	target_id = 0;
	break;
      case SIGVTALRM:
      case SIGPROF:
      	check_vtimer(proc_nr, signo);
      	/* fall-through */
      default:
	target_id = proc_id;
	break;
  }
  check_sig(target_id, signo, TRUE);
  mp->mp_procgrp = 0;

  if (signo == SIGSNDELAY && (rmp->mp_flags & DELAY_CALL)) {
	rmp->mp_flags &= ~DELAY_CALL;

	assert(!(rmp->mp_flags & PROC_STOPPED));

	if (rmp->mp_flags & (VFS_CALL | EVENT_CALL)) {
		stop_proc(rmp, FALSE);
		return OK;
	}

	check_pending(rmp);

	assert(!(rmp->mp_flags & DELAY_CALL));
  }

  if ((mproc[proc_nr].mp_flags & (IN_USE | EXITING)) == IN_USE) return OK;
  else return EDEADEPT;
}

/*===========================================================================*
 *				sig_proc				     *
 *===========================================================================*/
void sig_proc(struct mproc *rmp, int signo, int trace, int ksig)
{
  int slot, badignore;

  slot = (int) (rmp - mproc);
  if ((rmp->mp_flags & (IN_USE | EXITING)) != IN_USE) {
	panic("PM: signal %d sent to exiting process %d\n", signo, slot);
  }

  if (trace == TRUE && rmp->mp_tracer != NO_TRACER && signo != SIGKILL) {
	sigaddset(&rmp->mp_sigtrace, signo);
	if (!(rmp->mp_flags & TRACE_STOPPED)) trace_stop(rmp, signo);
	return;
  }

  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL)) {
	add_pending_signal(rmp, signo, ksig);
	if (!(rmp->mp_flags & (PROC_STOPPED | DELAY_CALL))) {
		stop_proc(rmp, FALSE);
	}
	return;
  }

  if (rmp->mp_flags & PRIV_PROC) {
   	if (rmp->mp_endpoint == PM_PROC_NR) return;

   	if (!ksig) {
 		sys_kill(rmp->mp_endpoint, signo);
 		return;
   	}

  	if (SIGS_IS_STACKTRACE(signo)) {
		sys_diagctl_stacktrace(rmp->mp_endpoint);
  	}

  	if (!SIGS_IS_TERMINATION(signo)) {
		message m;
		memset(&m, 0, sizeof(m));
		m.m_type = SIGS_SIGNAL_RECEIVED;
		m.m_pm_lsys_sigs_signal.num = signo;
		asynsend3(rmp->mp_endpoint, &m, AMF_NOREPLY);
		return;
	}

	sig_proc_exit(rmp, signo);
	return;
  }

  badignore = ksig && sigismember(&noign_sset, signo) &&
	  (sigismember(&rmp->mp_ignore, signo) ||
	   sigismember(&rmp->mp_sigmask, signo));

  if (!badignore && sigismember(&rmp->mp_ignore, signo)) return;

  if (!badignore && sigismember(&rmp->mp_sigmask, signo)) {
	add_pending_signal(rmp, signo, ksig);
	return;
  }

  if ((rmp->mp_flags & TRACE_STOPPED) && signo != SIGKILL) {
	add_pending_signal(rmp, signo, ksig);
	return;
  }

  if (!badignore && sigismember(&rmp->mp_catch, signo)) {
	if (!unpause(rmp)) {
		add_pending_signal(rmp, signo, ksig);
		return;
	}
	if (sig_send(rmp, signo)) return;

	printf("PM: %d can't catch signal %d - killing\n", rmp->mp_pid, signo);
  } else if (!badignore && sigismember(&ign_sset, signo)) {
	return;
  }

  sig_proc_exit(rmp, signo);
}

/*===========================================================================*
 *				sig_proc_exit				     *
 *===========================================================================*/
static void sig_proc_exit(struct mproc *rmp, int signo)
{
  rmp->mp_sigstatus = (char) signo;
  if (sigismember(&core_sset, signo)) {
	if (!(rmp->mp_flags & PRIV_PROC)) {
		printf("PM: coredump signal %d for %d / %s\n", signo,
			rmp->mp_pid, rmp->mp_name);
		sys_diagctl_stacktrace(rmp->mp_endpoint);
	}
	exit_proc(rmp, 0, TRUE);
  } else {
  	exit_proc(rmp, 0, FALSE);
  }
}

/*===========================================================================*
 *				check_sig				     *
 *===========================================================================*/
int check_sig(proc_id, signo, ksig)
pid_t proc_id;
int signo;
int ksig;
{
  struct mproc *rmp;
  int count;
  int error_code;

  if (signo < 0 || signo >= _NSIG) return EINVAL;

  if (proc_id == INIT_PID && signo == SIGKILL) return EINVAL;

  if (proc_id == -1 && signo == SIGTERM) sys_kill(RS_PROC_NR, signo);

  count = 0;
  error_code = ESRCH;
  for (rmp = &mproc[NR_PROCS - 1]; rmp >= &mproc[0]; rmp--) {
	if (!(rmp->mp_flags & IN_USE)) continue;

	if (proc_id > 0 && proc_id != rmp->mp_pid) continue;
	if (proc_id == 0 && mp->mp_procgrp != rmp->mp_procgrp) continue;
	if (proc_id == -1 && rmp->mp_pid <= INIT_PID) continue;
	if (proc_id < -1 && rmp->mp_procgrp != -proc_id) continue;

	if (proc_id == -1 && signo == SIGKILL && (rmp->mp_flags & PRIV_PROC))
		continue;

	if (rmp->mp_endpoint == VM_PROC_NR) continue;

	if (!ksig && SIGS_IS_LETHAL(signo) && (rmp->mp_flags & PRIV_PROC)) {
	    error_code = EPERM;
	    continue;
	}

	if (mp->mp_effuid != SUPER_USER
	    && mp->mp_realuid != rmp->mp_realuid
	    && mp->mp_effuid != rmp->mp_realuid
	    && mp->mp_realuid != rmp->mp_effuid
	    && mp->mp_effuid != rmp->mp_effuid) {
		error_code = EPERM;
		continue;
	}

	count++;
	if (signo == 0 || (rmp->mp_flags & EXITING)) continue;

	sig_proc(rmp, signo, TRUE, ksig);

	if (proc_id > 0) break;
  }

  if ((mp->mp_flags & (IN_USE | EXITING)) != IN_USE) return SUSPEND;
  return (count > 0) ? OK : error_code;
}

/*===========================================================================*
 *				check_pending				     *
 *===========================================================================*/
void check_pending(struct mproc *rmp)
{
  int i;
  int ksig;

  for (i = 1; i < _NSIG; i++) {
	if (sigismember(&rmp->mp_sigpending, i) &&
	    !sigismember(&rmp->mp_sigmask, i)) {
		ksig = sigismember(&rmp->mp_ksigpending, i);
		del_pending_signal(rmp, i);
		sig_proc(rmp, i, FALSE, ksig);

		if (rmp->mp_flags & (VFS_CALL | EVENT_CALL)) {
			assert(rmp->mp_flags & PROC_STOPPED);
			break;
		}
	}
  }
}

/*===========================================================================*
 *				restart_sigs				     *
 *===========================================================================*/
void restart_sigs(struct mproc *rmp)
{
  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL | EXITING)) return;

  if (rmp->mp_flags & TRACE_EXIT) {
	exit_proc(rmp, rmp->mp_exitstatus, FALSE);
  }
  else if (rmp->mp_flags & PROC_STOPPED) {
	assert(!(rmp->mp_flags & DELAY_CALL));

	check_pending(rmp);

	try_resume_proc(rmp);
  }
}

/*===========================================================================*
 *				unpause					     *
 *===========================================================================*/
static int unpause(struct mproc *rmp)
{
  message m;

  assert(!(rmp->mp_flags & (VFS_CALL | EVENT_CALL)));

  if (rmp->mp_flags & UNPAUSED) {
	assert((rmp->mp_flags & (DELAY_CALL | PROC_STOPPED)) == PROC_STOPPED);
	return TRUE;
  }

  if (rmp->mp_flags & DELAY_CALL) return FALSE;

  if (rmp->mp_flags & (WAITING | SIGSUSPENDED)) {
	stop_proc(rmp, FALSE);
	return TRUE;
  }

  if (!(rmp->mp_flags & PROC_STOPPED) && !stop_proc(rmp, TRUE)) return FALSE;

  memset(&m, 0, sizeof(m));
  m.m_type = VFS_PM_UNPAUSE;
  m.VFS_PM_ENDPT = rmp->mp_endpoint;

  tell_vfs(rmp, &m);

  return FALSE;
}

/*===========================================================================*
 *				sig_send				     *
 *===========================================================================*/
static int sig_send(struct mproc *rmp, int signo)
{
  struct sigmsg sigmsg;
  int i, r, sigflags, slot;

  assert(rmp->mp_flags & PROC_STOPPED);

  sigflags = rmp->mp_sigact[signo].sa_flags;
  slot = (int) (rmp - mproc);

  sigmsg.sm_mask = (rmp->mp_flags & SIGSUSPENDED) ? rmp->mp_sigmask2
						  : rmp->mp_sigmask;
  sigmsg.sm_signo = signo;
  sigmsg.sm_sighandler = (vir_bytes) rmp->mp_sigact[signo].sa_handler;
  sigmsg.sm_sigreturn = rmp->mp_sigreturn;

  for (i = 1; i < _NSIG; i++) {
	if (sigismember(&rmp->mp_sigact[signo].sa_mask, i))
		sigaddset(&rmp->mp_sigmask, i);
  }

  if (sigflags & SA_NODEFER) sigdelset(&rmp->mp_sigmask, signo);
  else sigaddset(&rmp->mp_sigmask, signo);

  if (sigflags & SA_RESETHAND) {
	sigdelset(&rmp->mp_catch, signo);
	rmp->mp_sigact[signo].sa_handler = SIG_DFL;
  }

  del_pending_signal(rmp, signo);

  r = sys_sigsend(rmp->mp_endpoint, &sigmsg);
  if (r == EFAULT || r == ENOMEM) return FALSE;
  if (r != OK) panic("sys_sigsend failed: %d", r);

  if (rmp->mp_flags & (WAITING | SIGSUSPENDED)) {
	rmp->mp_flags &= ~(WAITING | SIGSUSPENDED);
	reply(slot, EINTR);
	assert(!(rmp->mp_flags & UNPAUSED));
	try_resume_proc(rmp);
	assert(!(rmp->mp_flags & PROC_STOPPED));
  } else {
	assert(rmp->mp_flags & UNPAUSED);
  }

  return TRUE;
}

static void add_pending_signal(struct mproc *rmp, int signo, int ksig)
{
  sigaddset(&rmp->mp_sigpending, signo);
  if (ksig) sigaddset(&rmp->mp_ksigpending, signo);
}

static void del_pending_signal(struct mproc *rmp, int signo)
{
  sigdelset(&rmp->mp_sigpending, signo);
  sigdelset(&rmp->mp_ksigpending, signo);
}