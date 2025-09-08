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
static void check_parent(struct mproc *child, int try_cleanup);
static int tell_parent(struct mproc *child, vir_bytes addr);
static void tell_tracer(struct mproc *child);
static void tracer_died(struct mproc *child);
static void cleanup(struct mproc *rmp);

static int check_fork_capacity(const struct mproc *rmp);
static int find_free_child_slot(void);
static void init_child_common(struct mproc *parent, struct mproc *child, endpoint_t child_ep, int inherit_mask, int adjust_sched_for_priv_parent);

int do_fork(void)
{
  struct mproc *rmp;
  struct mproc *rmc;
  pid_t new_pid;
  int s;
  int child_slot;
  endpoint_t child_ep;
  message m;

  rmp = mp;
  s = check_fork_capacity(rmp);
  if (s != OK) return s;

  child_slot = find_free_child_slot();

  if ((s = vm_fork(rmp->mp_endpoint, child_slot, &child_ep)) != OK) {
	return s;
  }

  rmc = &mproc[child_slot];
  procs_in_use++;

  init_child_common(rmp, rmc, child_ep, IN_USE | DELAY_CALL | TAINTED, 1);

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
	sig_proc(rmc, SIGSTOP, TRUE, FALSE);

  return SUSPEND;
}

int do_srv_fork(void)
{
  struct mproc *rmp;
  struct mproc *rmc;
  int s;
  pid_t new_pid;
  int child_slot;
  endpoint_t child_ep;
  message m;

  if (mp->mp_endpoint != RS_PROC_NR)
	return EPERM;

  rmp = mp;
  s = check_fork_capacity(rmp);
  if (s != OK) return s;

  child_slot = find_free_child_slot();

  if ((s = vm_fork(rmp->mp_endpoint, child_slot, &child_ep)) != OK) {
	return s;
  }

  rmc = &mproc[child_slot];
  procs_in_use++;

  init_child_common(rmp, rmc, child_ep, IN_USE | PRIV_PROC | DELAY_CALL, 0);

  rmc->mp_realuid = m_in.m_lsys_pm_srv_fork.uid;
  rmc->mp_effuid = m_in.m_lsys_pm_srv_fork.uid;
  rmc->mp_svuid = m_in.m_lsys_pm_srv_fork.uid;
  rmc->mp_realgid = m_in.m_lsys_pm_srv_fork.gid;
  rmc->mp_effgid = m_in.m_lsys_pm_srv_fork.gid;
  rmc->mp_svgid = m_in.m_lsys_pm_srv_fork.gid;

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
	sig_proc(rmc, SIGSTOP, TRUE, FALSE);

  reply(rmc - mproc, OK);

  return rmc->mp_pid;
}

int do_exit(void)
{
  if (mp->mp_flags & PRIV_PROC) {
      printf("PM: system process %d (%s) tries to exit(), sending SIGKILL\n",
          mp->mp_endpoint, mp->mp_name);
      sys_kill(mp->mp_endpoint, SIGKILL);
  } else {
      exit_proc(mp, m_in.m_lc_pm_exit.status, FALSE);
  }
  return SUSPEND;
}

void exit_proc(struct mproc *rmp, int exit_status, int dump_core)
{
  int proc_nr, proc_nr_e;
  int r;
  pid_t procgrp;
  clock_t user_time, sys_time;
  message m;

  if (dump_core && rmp->mp_realuid != rmp->mp_effuid)
	dump_core = FALSE;

  if (dump_core && (rmp->mp_flags & PRIV_PROC))
	dump_core = FALSE;

  proc_nr = (int) (rmp - mproc);
  proc_nr_e = rmp->mp_endpoint;

  procgrp = (rmp->mp_pid == mp->mp_procgrp) ? mp->mp_procgrp : 0;

  if (rmp->mp_flags & ALARM_ON) set_alarm(rmp, (clock_t) 0);

  if ((r = sys_times(proc_nr_e, &user_time, &sys_time, NULL, NULL)) != OK)
  	panic("exit_proc: sys_times failed: %d", r);
  rmp->mp_child_utime += user_time;
  rmp->mp_child_stime += sys_time;

  if (!(rmp->mp_flags & PROC_STOPPED)) {
	if ((r = sys_stop(proc_nr_e)) != OK)
		panic("sys_stop failed: %d", r);
	rmp->mp_flags |= PROC_STOPPED;
  }

  if ((r = vm_willexit(proc_nr_e)) != OK) {
	panic("exit_proc: vm_willexit failed: %d", r);
  }

  if (proc_nr_e == INIT_PROC_NR) {
	printf("PM: INIT died with exit status %d; showing stacktrace\n", exit_status);
	sys_diagctl_stacktrace(proc_nr_e);
	return;
  }
  if (proc_nr_e == VFS_PROC_NR) {
	panic("exit_proc: VFS died: %d", r);
  }

  memset(&m, 0, sizeof(m));
  m.m_type = dump_core ? VFS_PM_DUMPCORE : VFS_PM_EXIT;
  m.VFS_PM_ENDPT = rmp->mp_endpoint;

  if (dump_core) {
	m.VFS_PM_TERM_SIG = rmp->mp_sigstatus;
	m.VFS_PM_PATH = rmp->mp_name;
  }

  tell_vfs(rmp, &m);

  if (rmp->mp_flags & PRIV_PROC) {
	if ((r = sys_clear(rmp->mp_endpoint)) != OK)
		panic("exit_proc: sys_clear failed: %d", r);
  }

  rmp->mp_flags &= (IN_USE | VFS_CALL | PRIV_PROC | TRACE_EXIT | PROC_STOPPED);
  rmp->mp_flags |= EXITING;

  rmp->mp_exitstatus = (char) exit_status;

  if (!dump_core)
	zombify(rmp);

  for (struct mproc *child = &mproc[0]; child < &mproc[NR_PROCS]; child++) {
	if (!(child->mp_flags & IN_USE)) continue;
	if (child->mp_tracer == proc_nr) {
		tracer_died(child);
	}
	if (child->mp_parent == proc_nr) {
		child->mp_parent = INIT_PROC_NR;
		if (child->mp_flags & VFS_CALL)
			child->mp_flags |= NEW_PARENT;
		if (child->mp_flags & ZOMBIE)
			check_parent(child, TRUE);
	}
  }

  if (procgrp != 0) check_sig(-procgrp, SIGHUP, FALSE);
}

void exit_restart(struct mproc *rmp)
{
  int r;

  if ((r = sched_stop(rmp->mp_scheduler, rmp->mp_endpoint)) != OK) {
	printf("PM: The scheduler did not want to give up scheduling %s, ret=%d.\n",
		rmp->mp_name, r);
  }

  rmp->mp_scheduler = NONE;

  if (!(rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE | TOLD_PARENT)))
	zombify(rmp);

  if (!(rmp->mp_flags & PRIV_PROC)) {
	if ((r = sys_clear(rmp->mp_endpoint)) != OK)
		panic("exit_restart: sys_clear failed: %d", r);
  }

  if ((r = vm_exit(rmp->mp_endpoint)) != OK) {
  	panic("exit_restart: vm_exit failed: %d", r);
  }

  if (rmp->mp_flags & TRACE_EXIT) {
	mproc[rmp->mp_tracer].mp_reply.m_pm_lc_ptrace.data = 0;
	reply(rmp->mp_tracer, OK);
  }

  if (rmp->mp_flags & TOLD_PARENT)
	cleanup(rmp);
}

int do_wait4(void)
{
  struct mproc *rp;
  vir_bytes addr;
  int i, pidarg, options, children, waited_for;

  pidarg  = m_in.m_lc_pm_wait4.pid;
  options = m_in.m_lc_pm_wait4.options;
  addr    = m_in.m_lc_pm_wait4.addr;
  if (pidarg == 0) pidarg = -mp->mp_procgrp;

  children = 0;
  for (rp = &mproc[0]; rp < &mproc[NR_PROCS]; rp++) {
	if ((rp->mp_flags & (IN_USE | TOLD_PARENT)) != IN_USE) continue;
	if (rp->mp_parent != who_p && rp->mp_tracer != who_p) continue;
	if (rp->mp_parent != who_p && (rp->mp_flags & ZOMBIE)) continue;

	if (pidarg  > 0 && pidarg != rp->mp_pid) continue;
	if (pidarg < -1 && -pidarg != rp->mp_procgrp) continue;

	children++;

	if (rp->mp_tracer == who_p) {
		if (rp->mp_flags & TRACE_ZOMBIE) {
			tell_tracer(rp);
			check_parent(rp, TRUE);
			return SUSPEND;
		}
		if (rp->mp_flags & TRACE_STOPPED) {
			for (i = 1; i < _NSIG; i++) {
				if (sigismember(&rp->mp_sigtrace, i)) {
					sigdelset(&rp->mp_sigtrace, i);
					mp->mp_reply.m_pm_lc_wait4.status = W_STOPCODE(i);
					return rp->mp_pid;
				}
			}
		}
	}

	if (rp->mp_parent == who_p) {
		if (rp->mp_flags & ZOMBIE) {
			waited_for = tell_parent(rp, addr);
			if (waited_for && !(rp->mp_flags & (VFS_CALL | EVENT_CALL)))
				cleanup(rp);
			return SUSPEND;
		}
	}
  }

  if (children > 0) {
	if (options & WNOHANG) {
		return 0;
	}
	mp->mp_flags |= WAITING;
	mp->mp_wpid = (pid_t) pidarg;
	mp->mp_waddr = addr;
	return SUSPEND;
  } else {
	return ECHILD;
  }
}

int wait_test(struct mproc *rmp, struct mproc *child)
{
  int parent_waiting, right_child;
  pid_t pidarg;

  pidarg = rmp->mp_wpid;
  parent_waiting = rmp->mp_flags & WAITING;
  right_child =
  	(pidarg == -1 || pidarg == child->mp_pid || -pidarg == child->mp_procgrp);

  return (parent_waiting && right_child);
}

static void zombify(struct mproc *rmp)
{
  struct mproc *t_mp;

  if (rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE))
	panic("zombify: process was already a zombie");

  if (rmp->mp_tracer != NO_TRACER && rmp->mp_tracer != rmp->mp_parent) {
	rmp->mp_flags |= TRACE_ZOMBIE;

	t_mp = &mproc[rmp->mp_tracer];

	if (!wait_test(t_mp, rmp))
		return;

	tell_tracer(rmp);
  } else {
	rmp->mp_flags |= ZOMBIE;
  }

  check_parent(rmp, FALSE);
}

static void check_parent(struct mproc *child, int try_cleanup)
{
  struct mproc *p_mp;

  p_mp = &mproc[child->mp_parent];

  if (p_mp->mp_flags & EXITING) {
  }
  else if (wait_test(p_mp, child)) {
	if (!tell_parent(child, p_mp->mp_waddr))
		try_cleanup = FALSE;
	if (try_cleanup && !(child->mp_flags & (VFS_CALL | EVENT_CALL)))
		cleanup(child);
  }
  else {
	sig_proc(p_mp, SIGCHLD, TRUE, FALSE);
  }
}

static int tell_parent(struct mproc *child, vir_bytes addr)
{
  struct rusage r_usage;
  int mp_parent;
  struct mproc *parent;
  int r;

  mp_parent= child->mp_parent;
  if (mp_parent <= 0)
	panic("tell_parent: bad value in mp_parent: %d", mp_parent);
  if (!(child->mp_flags & ZOMBIE))
  	panic("tell_parent: child not a zombie");
  if (child->mp_flags & TOLD_PARENT)
	panic("tell_parent: telling parent again");
  parent = &mproc[mp_parent];

  if (addr) {
	memset(&r_usage, 0, sizeof(r_usage));
	set_rusage_times(&r_usage, child->mp_child_utime, child->mp_child_stime);

	if ((r = sys_datacopy(SELF, (vir_bytes)&r_usage, parent->mp_endpoint,
	    addr, sizeof(r_usage))) != OK) {
		reply(child->mp_parent, r);
		return FALSE;
	}
  }

  parent->mp_reply.m_pm_lc_wait4.status =
	W_EXITCODE(child->mp_exitstatus, child->mp_sigstatus);
  reply(child->mp_parent, child->mp_pid);
  parent->mp_flags &= ~WAITING;
  child->mp_flags &= ~ZOMBIE;
  child->mp_flags |= TOLD_PARENT;

  parent->mp_child_utime += child->mp_child_utime;
  parent->mp_child_stime += child->mp_child_stime;

  return TRUE;
}

static void tell_tracer(struct mproc *child)
{
  int mp_tracer;
  struct mproc *tracer;

  mp_tracer = child->mp_tracer;
  if (mp_tracer <= 0)
	panic("tell_tracer: bad value in mp_tracer: %d", mp_tracer);
  if (!(child->mp_flags & TRACE_ZOMBIE))
  	panic("tell_tracer: child not a zombie");
  tracer = &mproc[mp_tracer];

  tracer->mp_reply.m_pm_lc_wait4.status =
	W_EXITCODE(child->mp_exitstatus, (child->mp_sigstatus & 0377));
  reply(child->mp_tracer, child->mp_pid);
  tracer->mp_flags &= ~WAITING;
  child->mp_flags &= ~TRACE_ZOMBIE;
  child->mp_flags |= ZOMBIE;
}

static void tracer_died(struct mproc *child)
{
  child->mp_tracer = NO_TRACER;
  child->mp_flags &= ~TRACE_EXIT;

  if (!(child->mp_flags & EXITING)) {
	sig_proc(child, SIGKILL, TRUE, FALSE);
	return;
  }

  if (child->mp_flags & TRACE_ZOMBIE) {
	child->mp_flags &= ~TRACE_ZOMBIE;
	child->mp_flags |= ZOMBIE;
	check_parent(child, TRUE);
  }
}

static void cleanup(struct mproc *rmp)
{
  rmp->mp_pid = 0;
  rmp->mp_flags = 0;
  rmp->mp_child_utime = 0;
  rmp->mp_child_stime = 0;
  procs_in_use--;
}

static int check_fork_capacity(const struct mproc *rmp)
{
  if ((procs_in_use == NR_PROCS) ||
      (procs_in_use >= NR_PROCS - LAST_FEW && rmp->mp_effuid != 0)) {
  	printf("PM: warning, process table is full!\n");
  	return EAGAIN;
  }
  return OK;
}

static int find_free_child_slot(void)
{
  static unsigned int next_child = 0;
  int n = 0;
  do {
        next_child = (next_child + 1) % NR_PROCS;
	n++;
  } while ((mproc[next_child].mp_flags & IN_USE) && n <= NR_PROCS);
  if (n > NR_PROCS)
	panic("find_free_child_slot: no free child slot");
  if (next_child >= NR_PROCS || (mproc[next_child].mp_flags & IN_USE))
	panic("find_free_child_slot: wrong child slot: %d", next_child);
  return (int)next_child;
}

static void init_child_common(struct mproc *parent, struct mproc *child, endpoint_t child_ep, int inherit_mask, int adjust_sched_for_priv_parent)
{
  int i;
  int child_slot = (int)(child - mproc);

  *child = *parent;
  child->mp_sigact = mpsigact[child_slot];
  memcpy(child->mp_sigact, parent->mp_sigact, sizeof(mpsigact[child_slot]));
  child->mp_parent = who_p;
  if (!(child->mp_trace_flags & TO_TRACEFORK)) {
	child->mp_tracer = NO_TRACER;
	child->mp_trace_flags = 0;
	(void)sigemptyset(&child->mp_sigtrace);
  }

  if (adjust_sched_for_priv_parent && (child->mp_flags & PRIV_PROC)) {
	assert(child->mp_scheduler == NONE);
	child->mp_scheduler = SCHED_PROC_NR;
  }

  child->mp_flags &= inherit_mask;
  child->mp_child_utime = 0;
  child->mp_child_stime = 0;
  child->mp_exitstatus = 0;
  child->mp_sigstatus = 0;
  child->mp_endpoint = child_ep;
  for (i = 0; i < NR_ITIMERS; i++)
	child->mp_interval[i] = 0;
  child->mp_started = getticks();

  assert(child->mp_eventsub == NO_EVENTSUB);
}