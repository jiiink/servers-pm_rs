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

static int unpause_proc(struct mproc *rmp);
static int send_signal(struct mproc *rmp, int signo);
static void exit_signal_process(struct mproc *rmp, int signo);

int do_sigaction(void)
{
  int r, sig_nr;
  struct sigaction svec;
  struct sigaction *svp;

  if (mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL))
      return(EINVAL);

  sig_nr = m_in.m_lc_pm_sig.nr;
  if (sig_nr < 1 || sig_nr >= _NSIG) return(EINVAL);

  svp = &mp->mp_sigact[sig_nr];
  if (m_in.m_lc_pm_sig.oact != 0) {
	r = sys_datacopy(PM_PROC_NR,(vir_bytes) svp, who_e,
		m_in.m_lc_pm_sig.oact, (phys_bytes) sizeof(svec));
	if (r != OK) return(r);
  }

  if (m_in.m_lc_pm_sig.act == 0)
  	return(OK);

  r = sys_datacopy(who_e, m_in.m_lc_pm_sig.act, PM_PROC_NR, (vir_bytes) &svec,
	  (phys_bytes) sizeof(svec));
  if (r != OK) return(r);

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
  return(OK);
}

int do_sigpending(void)
{
  if (mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL))
      return(EINVAL);

  mp->mp_reply.m_pm_lc_sigset.set = mp->mp_sigpending;
  return OK;
}

int do_sigprocmask(void)
{
  sigset_t set;
  int i;

  if (mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL))
      return(EINVAL);

  set = m_in.m_lc_pm_sigset.set;
  mp->mp_reply.m_pm_lc_sigset.set = mp->mp_sigmask;

  switch (m_in.m_lc_pm_sigset.how) {
      case SIG_BLOCK:
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	for (i = 1; i < _NSIG; i++) {
		if (sigismember(&set, i))
			sigaddset(&mp->mp_sigmask, i);
	}
	break;

      case SIG_UNBLOCK:
	for (i = 1; i < _NSIG; i++) {
		if (sigismember(&set, i))
			sigdelset(&mp->mp_sigmask, i);
	}
	check_pending(mp);
	break;

      case SIG_SETMASK:
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	mp->mp_sigmask = set;
	check_pending(mp);
	break;

      default:
	return(EINVAL);
  }
  return OK;
}

int do_sigsuspend(void)
{
  if (mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL))
      return(EINVAL);

  mp->mp_sigmask2 = mp->mp_sigmask;
  mp->mp_sigmask = m_in.m_lc_pm_sigset.set;
  sigdelset(&mp->mp_sigmask, SIGKILL);
  sigdelset(&mp->mp_sigmask, SIGSTOP);
  mp->mp_flags |= SIGSUSPENDED;
  check_pending(mp);
  return(SUSPEND);
}

int do_sigreturn(void)
{
  int r;

  if (mp->mp_flags & (PROC_STOPPED | VFS_CALL | UNPAUSED | EVENT_CALL))
      return(EINVAL);

  mp->mp_sigmask = m_in.m_lc_pm_sigset.set;
  sigdelset(&mp->mp_sigmask, SIGKILL);
  sigdelset(&mp->mp_sigmask, SIGSTOP);

  r = sys_sigreturn(who_e, (struct sigmsg *)m_in.m_lc_pm_sigset.ctx);
  check_pending(mp);
  return(r);
}

int do_kill(void)
{
  return check_sig(m_in.m_lc_pm_sig.pid, m_in.m_lc_pm_sig.nr, FALSE);
}

int do_srv_kill(void)
{
  if (mp->mp_endpoint != RS_PROC_NR)
	return EPERM;

  return check_sig(m_in.m_rs_pm_srv_kill.pid, m_in.m_rs_pm_srv_kill.nr, TRUE);
}

static int stop_proc(struct mproc *rmp, int may_delay)
{
  int r;

  if (rmp->mp_flags & (PROC_STOPPED | DELAY_CALL | UNPAUSED))
      return(FALSE);

  r = sys_delay_stop(rmp->mp_endpoint);

  switch (r) {
  case OK:
	rmp->mp_flags |= PROC_STOPPED;
	return TRUE;

  case EBUSY:
	if (!may_delay)
		panic("stop_proc: unexpected delay call");

	rmp->mp_flags |= DELAY_CALL;
	return FALSE;

  default:
	panic("sys_delay_stop failed: %d", r);
  }
}

static void try_resume_proc(struct mproc *rmp)
{
  int r;

  if (!(rmp->mp_flags & PROC_STOPPED))
      return;

  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL | EXITING))
	return;

  if ((r = sys_resume(rmp->mp_endpoint)) != OK)
	panic("sys_resume failed: %d", r);

  rmp->mp_flags &= ~(PROC_STOPPED | UNPAUSED);
}

int process_ksig(endpoint_t proc_nr_e, int signo)
{
  register struct mproc *rmp;
  int proc_nr;
  pid_t proc_id, id;

  if(pm_isokendpt(proc_nr_e, &proc_nr) != OK) {
	printf("PM: process_ksig: %d?? not ok\n", proc_nr_e);
	return EDEADEPT;
  }
  rmp = &mproc[proc_nr];
  if ((rmp->mp_flags & (IN_USE | EXITING)) != IN_USE) {
	return EDEADEPT;
  }
  proc_id = rmp->mp_pid;
  mp = &mproc[0];
  mp->mp_procgrp = rmp->mp_procgrp;

  switch (signo) {
      case SIGINT:
      case SIGQUIT:
      case SIGWINCH:
      case SIGINFO:
  	id = 0; break;
      case SIGVTALRM:
      case SIGPROF:
      	check_vtimer(proc_nr, signo);
        id = proc_id;
        break;
      default:
        id = proc_id;
        break;
  }
  check_sig(id, signo, TRUE);
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

  if ((mproc[proc_nr].mp_flags & (IN_USE | EXITING)) == IN_USE)  {
      return OK;
  }
  else {
      return EDEADEPT;
  }
}

void sig_proc(register struct mproc *rmp, int signo, int trace, int ksig)
{
  if ((rmp->mp_flags & (IN_USE | EXITING)) != IN_USE)
      panic("PM: signal %d sent to exiting process %d\n", signo, rmp->mp_endpoint);

  if (trace && rmp->mp_tracer != NO_TRACER && signo != SIGKILL) {
	sigaddset(&rmp->mp_sigtrace, signo);
	if (!(rmp->mp_flags & TRACE_STOPPED))
		trace_stop(rmp, signo);
	return;
  }

  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL)) {
	sigaddset(&rmp->mp_sigpending, signo);
	if(ksig)
		sigaddset(&rmp->mp_ksigpending, signo);

	if (!(rmp->mp_flags & (PROC_STOPPED | DELAY_CALL))) {
		stop_proc(rmp, FALSE);
	}
	return;
  }

  if(rmp->mp_flags & PRIV_PROC) {
   	if(rmp->mp_endpoint == PM_PROC_NR) return;

   	if(!ksig) {
 		sys_kill(rmp->mp_endpoint, signo);
 		return;
   	}

  	if(SIGS_IS_STACKTRACE(signo)) {
		sys_diagctl_stacktrace(rmp->mp_endpoint);
  	}

  	if(!SIGS_IS_TERMINATION(signo)) {
		message m;
		m.m_type = SIGS_SIGNAL_RECEIVED;
		m.m_pm_lsys_sigs_signal.num = signo;
		asynsend3(rmp->mp_endpoint, &m, AMF_NOREPLY);
	}
	else {
		exit_signal_process(rmp, signo);
	}
	return;
  }

  if (!sigismember(&noign_sset, signo) && sigismember(&rmp->mp_ignore, signo)) {
	return;
  }
  
  if (!sigismember(&noign_sset, signo) && sigismember(&rmp->mp_sigmask, signo)) {
	sigaddset(&rmp->mp_sigpending, signo);
	if(ksig)
		sigaddset(&rmp->mp_ksigpending, signo);
	return;
  }

  if ((rmp->mp_flags & TRACE_STOPPED) && signo != SIGKILL) {
	sigaddset(&rmp->mp_sigpending, signo);
	if(ksig)
		sigaddset(&rmp->mp_ksigpending, signo);
	return;
  }
  if (!sigismember(&noign_sset, signo) && sigismember(&rmp->mp_catch, signo)) {
	if (!unpause_proc(rmp)) {
		sigaddset(&rmp->mp_sigpending, signo);
		if(ksig)
			sigaddset(&rmp->mp_ksigpending, signo);
		return;
	}

	if (send_signal(rmp, signo))
		return;

	printf("PM: %d can't catch signal %d - killing\n",
		rmp->mp_pid, signo);
  }
  else if (!sigismember(&noign_sset, signo) && sigismember(&ign_sset, signo)) {
	return;
  }

  exit_signal_process(rmp, signo);
}

static void exit_signal_process(struct mproc *rmp, int signo)
{
  rmp->mp_sigstatus = (char) signo;
  if (sigismember(&core_sset, signo)) {
	if(!(rmp->mp_flags & PRIV_PROC)) {
		printf("PM: coredump signal %d for %d / %s\n", signo,
			rmp->mp_pid, rmp->mp_name);
		sys_diagctl_stacktrace(rmp->mp_endpoint);
	}
	exit_proc(rmp, 0, TRUE);
  }
  else {
  	exit_proc(rmp, 0, FALSE);
  }
}

int check_sig(pid_t proc_id, int signo, int ksig)
{
  register struct mproc *rmp;
  int count = 0;
  int error_code = ESRCH;

  if (signo < 0 || signo >= _NSIG) return(EINVAL);

  if (proc_id == INIT_PID && signo == SIGKILL) return(EINVAL);

  if (proc_id == -1 && signo == SIGTERM)
      sys_kill(RS_PROC_NR, signo);

  for (rmp = &mproc[NR_PROCS-1]; rmp >= &mproc[0]; rmp--) {
	if (!(rmp->mp_flags & IN_USE)) continue;

	if (proc_id > 0 && proc_id != rmp->mp_pid) continue;
	if (proc_id == 0 && mp->mp_procgrp != rmp->mp_procgrp) continue;
	if (proc_id == -1 && rmp->mp_pid <= INIT_PID) continue;
	if (proc_id < -1 && rmp->mp_procgrp != -proc_id) continue;

	if (proc_id == -1 && signo == SIGKILL && (rmp->mp_flags & PRIV_PROC)) continue;

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

  if ((mp->mp_flags & (IN_USE | EXITING)) != IN_USE) return(SUSPEND);
  return(count > 0 ? OK : error_code);
}

void check_pending(struct mproc *rmp)
{
  int i, ksig;
  for (i = 1; i < _NSIG; i++) {
	if (sigismember(&rmp->mp_sigpending, i) &&
		!sigismember(&rmp->mp_sigmask, i)) {
		ksig = sigismember(&rmp->mp_ksigpending, i);
		sigdelset(&rmp->mp_sigpending, i);
		sigdelset(&rmp->mp_ksigpending, i);
		sig_proc(rmp, i, FALSE, ksig);

		if (rmp->mp_flags & (VFS_CALL | EVENT_CALL)) {
			assert(rmp->mp_flags & PROC_STOPPED);
			break;
		}
	}
  }
}

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

static int unpause_proc(struct mproc *rmp)
{
  message m;

  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL))
      return FALSE;

  if (rmp->mp_flags & UNPAUSED) {
	assert((rmp->mp_flags & (DELAY_CALL | PROC_STOPPED)) == PROC_STOPPED);
	return TRUE;
  }

  if (rmp->mp_flags & DELAY_CALL)
	return FALSE;

  if (rmp->mp_flags & (WAITING | SIGSUSPENDED)) {
	stop_proc(rmp, FALSE);
	return TRUE;
  }

  if (!(rmp->mp_flags & PROC_STOPPED) && !stop_proc(rmp, TRUE))
	return FALSE;

  memset(&m, 0, sizeof(m));
  m.m_type = VFS_PM_UNPAUSE;
  m.VFS_PM_ENDPT = rmp->mp_endpoint;

  tell_vfs(rmp, &m);

  return FALSE;
}

static int send_signal(struct mproc *rmp, int signo)
{
  struct sigmsg sigmsg;
  int i, r, sigflags, slot;

  assert(rmp->mp_flags & PROC_STOPPED);

  sigflags = rmp->mp_sigact[signo].sa_flags;
  slot = (int) (rmp - mproc);

  sigmsg.sm_mask = (rmp->mp_flags & SIGSUSPENDED) ? rmp->mp_sigmask2 : rmp->mp_sigmask;
  sigmsg.sm_signo = signo;
  sigmsg.sm_sighandler = (vir_bytes) rmp->mp_sigact[signo].sa_handler;
  sigmsg.sm_sigreturn = rmp->mp_sigreturn;
  for (i = 1; i < _NSIG; i++) {
	if (sigismember(&rmp->mp_sigact[signo].sa_mask, i))
		sigaddset(&rmp->mp_sigmask, i);
  }

  if (sigflags & SA_NODEFER)
	sigdelset(&rmp->mp_sigmask, signo);
  else
	sigaddset(&rmp->mp_sigmask, signo);

  if (sigflags & SA_RESETHAND) {
	sigdelset(&rmp->mp_catch, signo);
	rmp->mp_sigact[signo].sa_handler = SIG_DFL;
  }
  sigdelset(&rmp->mp_sigpending, signo);
  sigdelset(&rmp->mp_ksigpending, signo);

  r = sys_sigsend(rmp->mp_endpoint, &sigmsg);
  if(r == EFAULT || r == ENOMEM) {
	return(FALSE);
  }
  if (r != OK) {
	panic("sys_sigsend failed: %d", r);
  }

  if (rmp->mp_flags & (WAITING | SIGSUSPENDED)) {
	rmp->mp_flags &= ~(WAITING | SIGSUSPENDED);
	reply(slot, EINTR);
	try_resume_proc(rmp);
	assert(!(rmp->mp_flags & PROC_STOPPED));
  } else {
	assert(rmp->mp_flags & UNPAUSED);
  }

  return(TRUE);
}