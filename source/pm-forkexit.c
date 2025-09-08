/* This file deals with creating processes (via FORK) and deleting them (via
 * EXIT/WAIT4).  When a process forks, a new slot in the 'mproc' table is
 * allocated for it, and a copy of the parent's core image is made for the
 * child.  Then the kernel and file system are informed.  A process is removed
 * from the 'mproc' table when two events have occurred: (1) it has exited or
 * been killed by a signal, and (2) the parent has done a WAIT4.  If the
 * process exits first, it continues to occupy a slot until the parent does a
 * WAIT4.
 *
 * The entry points into this file are:
 *   do_fork:		perform the FORK system call
 *   do_srv_fork:	special FORK, used by RS to create sys services
 *   do_exit:		perform the EXIT system call (by calling exit_proc())
 *   exit_proc:		actually do the exiting, and tell VFS about it
 *   exit_restart:	continue exiting a process after VFS has replied
 *   do_wait4:		perform the WAIT4 system call
 *   wait_test:		check whether a parent is waiting for a child
 */

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

#define RESERVED_FOR_ROOT            2	/* last few slots reserved for superuser */

static void zombify(struct mproc *rmp);
static void check_parent(struct mproc *child, int try_cleanup);
static int tell_parent(struct mproc *child, vir_bytes addr);
static void tell_tracer(struct mproc *child);
static void tracer_died(struct mproc *child);
static void cleanup(register struct mproc *rmp);
static int fork_common(struct mproc *rmp, uid_t ruid, gid_t rgid);

/*===========================================================================*
 *				fork_common				     *
 *===========================================================================*/
static int fork_common(struct mproc *rmp, uid_t ruid, gid_t rgid)
{
  register struct mproc *rmc;	/* pointer to child */
  pid_t new_pid;
  static unsigned int next_child = 0; /* Static to preserve value across calls */
  int i, n_attempts = 0, s;
  endpoint_t child_ep;
  message m;

  /* Check for available slots. */
  if ((procs_in_use == NR_PROCS) ||
  		(procs_in_use >= NR_PROCS - RESERVED_FOR_ROOT && rmp->mp_effuid != 0))
  {
  	printf("PM: warning, process table is full!\n");
  	return(EAGAIN);
  }

  /* Find a slot in 'mproc' for the child process. A slot must exist. */
  do {
        next_child = (next_child + 1) % NR_PROCS;
	n_attempts++;
  } while((mproc[next_child].mp_flags & IN_USE) && n_attempts <= NR_PROCS);

  if(n_attempts > NR_PROCS || (mproc[next_child].mp_flags & IN_USE)) {
	panic("fork_common: can't find child slot");
  }

  /* Ask VM to create memory for the new process. */
  if((s = vm_fork(rmp->mp_endpoint, next_child, &child_ep)) != OK) {
	return s;
  }

  /* PM may not fail fork after call to vm_fork(), as VM calls sys_fork(). */

  rmc = &mproc[next_child];
  /* Set up the child and its memory map; copy its 'mproc' slot from parent. */
  procs_in_use++;
  *rmc = *rmp;			/* copy parent's process slot to child's */
  rmc->mp_sigact = mpsigact[next_child];	/* restore mp_sigact ptr */
  memcpy(rmc->mp_sigact, rmp->mp_sigact, sizeof(mpsigact[next_child]));
  rmc->mp_parent = (int)(rmp - mproc);		/* record child's parent (slot number) */
  if (!(rmc->mp_trace_flags & TO_TRACEFORK)) {
	rmc->mp_tracer = NO_TRACER;		/* no tracer attached */
	rmc->mp_trace_flags = 0;
	(void) sigemptyset(&rmc->mp_sigtrace);
  }

  /* Some system servers like to call regular fork, such as RS spawning
   * recovery scripts; in this case PM will take care of their scheduling
   * because RS cannot do so for non-system processes */
  if (rmc->mp_flags & PRIV_PROC) {
	assert(rmc->mp_scheduler == NONE);
	rmc->mp_scheduler = SCHED_PROC_NR;
  }

  /* Inherit only these flags. In normal fork(), PRIV_PROC is not inherited.
   * For srv_fork, PRIV_PROC is inherited.
   */
  rmc->mp_flags &= (IN_USE|DELAY_CALL|TAINTED|PRIV_PROC);
  rmc->mp_child_utime = 0;		/* reset administration */
  rmc->mp_child_stime = 0;		/* reset administration */
  rmc->mp_exitstatus = 0;
  rmc->mp_sigstatus = 0;
  rmc->mp_endpoint = child_ep;		/* passed back by VM */
  for (i = 0; i < NR_ITIMERS; i++)
	rmc->mp_interval[i] = 0;	/* reset timer intervals */
  rmc->mp_started = getticks();		/* remember start time, for ps(1) */

  assert(rmc->mp_eventsub == NO_EVENTSUB);

  /* Find a free pid for the child and put it in the table. */
  new_pid = get_free_pid();
  rmc->mp_pid = new_pid;	/* assign pid to child */

  /* Set UID/GID for srv_fork. For regular fork, these values are copied from parent in *rmc = *rmp; */
  rmc->mp_realuid = ruid;
  rmc->mp_effuid = ruid;
  rmc->mp_svuid = ruid;
  rmc->mp_realgid = rgid;
  rmc->mp_effgid = rgid;
  rmc->mp_svgid = rgid;

  memset(&m, 0, sizeof(m));
  m.m_type = (rmp->mp_flags & PRIV_PROC) ? VFS_PM_SRV_FORK : VFS_PM_FORK;
  m.VFS_PM_ENDPT = rmc->mp_endpoint;
  m.VFS_PM_PENDPT = rmp->mp_endpoint;
  m.VFS_PM_CPID = rmc->mp_pid;
  m.VFS_PM_REUID = rmc->mp_realuid;
  m.VFS_PM_REGID = rmc->mp_realgid;

  tell_vfs(rmc, &m);

  /* Tell the tracer, if any, about the new child */
  if (rmc->mp_tracer != NO_TRACER)
	sig_proc(rmc, SIGSTOP, TRUE /*trace*/, FALSE /* ksig */);

  /* If this is a privileged fork (srv_fork), reply immediately. */
  if (rmp->mp_flags & PRIV_PROC) {
      reply((int)(rmc-mproc), OK);
      return rmc->mp_pid;
  }

  /* For regular fork, reply will be sent after VFS responds. */
  return SUSPEND;
}

/*===========================================================================*
 *				do_fork					     *
 *===========================================================================*/
int
do_fork(void)
{
/* The process pointed to by 'mp' has forked. Create a child process. */
  struct mproc *rmp_parent = mp;
  return fork_common(rmp_parent, rmp_parent->mp_realuid, rmp_parent->mp_realgid);
}

/*===========================================================================*
 *				do_srv_fork				     *
 *===========================================================================*/
int
do_srv_fork(void)
{
/* The process pointed to by 'mp' (RS) has requested to fork a new service. */
  struct mproc *rmp_parent = mp;

  /* Only RS is allowed to use srv_fork. */
  if (rmp_parent->mp_endpoint != RS_PROC_NR)
	return EPERM;

  /* Delegate to common fork logic, passing specified UID/GID. */
  return fork_common(rmp_parent, m_in.m_lsys_pm_srv_fork.uid, m_in.m_lsys_pm_srv_fork.gid);
}

/*===========================================================================*
 *				do_exit					     *
 *===========================================================================*/
int
do_exit(void)
{
 /* Perform the exit(status) system call. The real work is done by exit_proc(),
  * which is also called when a process is killed by a signal. System processes
  * do not use PM's exit() to terminate. If they try to, we warn the user
  * and send a SIGKILL signal to the system process.
  */
  struct mproc *current_mp = mp;

  if(current_mp->mp_flags & PRIV_PROC) {
      printf("PM: system process %d (%s) tries to exit(), sending SIGKILL\n",
          current_mp->mp_endpoint, current_mp->mp_name);
      sys_kill(current_mp->mp_endpoint, SIGKILL);
  }
  else {
      exit_proc(current_mp, m_in.m_lc_pm_exit.status, FALSE /*dump_core*/);
  }
  return(SUSPEND);		/* can't communicate from beyond the grave */
}

/*===========================================================================*
 *				exit_proc_cleanup_state			     *
 *===========================================================================*/
static void exit_proc_cleanup_state(struct mproc *rmp) {
    int r;
    endpoint_t proc_nr_e = rmp->mp_endpoint;

    /* Tell the kernel the process is no longer runnable to prevent it from
     * being scheduled in between the following steps.
     */
    if (!(rmp->mp_flags & PROC_STOPPED)) {
        if ((r = sys_stop(proc_nr_e)) != OK)
            panic("sys_stop failed for endpoint %d: %d", proc_nr_e, r);
        rmp->mp_flags |= PROC_STOPPED;
    }

    /* Inform VM that the process is about to exit. */
    if((r = vm_willexit(proc_nr_e)) != OK) {
        panic("exit_proc: vm_willexit failed for endpoint %d: %d", proc_nr_e, r);
    }
}

/*===========================================================================*
 *				exit_proc_notify_vfs_events		     *
 *===========================================================================*/
static void exit_proc_notify_vfs_events(struct mproc *rmp, int dump_core) {
    message m;

    /* Tell VFS about the exiting process. */
    memset(&m, 0, sizeof(m));
    m.m_type = dump_core ? VFS_PM_DUMPCORE : VFS_PM_EXIT;
    m.VFS_PM_ENDPT = rmp->mp_endpoint;

    if (dump_core) {
        m.VFS_PM_TERM_SIG = rmp->mp_sigstatus;
        m.VFS_PM_PATH = rmp->mp_name;
    }
    tell_vfs(rmp, &m);
}

/*===========================================================================*
 *				exit_proc				     *
 *===========================================================================*/
void
exit_proc(
	register struct mproc *rmp,	/* pointer to the process to be terminated */
	int exit_status,		/* the process' exit status (for parent) */
	int dump_core			/* flag indicating whether to dump core */
)
{
/* A process is done. Release most of the process' possessions. If its
 * parent is waiting, release the rest, else keep the process slot and
 * become a zombie.
 */
  register int proc_nr;
  clock_t user_time, sys_time;
  pid_t procgrp_of_session_leader;
  int r;

  /* Do not create core files for set uid execution */
  if (dump_core && rmp->mp_realuid != rmp->mp_effuid)
	dump_core = FALSE;

  /* System processes are destroyed before informing VFS, meaning that VFS can
   * not get their CPU state, so we can't generate a coredump for them either.
   */
  if (dump_core && (rmp->mp_flags & PRIV_PROC))
	dump_core = FALSE;

  proc_nr = (int) (rmp - mproc);	/* get process slot number */

  /* Remember a session leader's process group. */
  procgrp_of_session_leader = (rmp->mp_pid == mp->mp_procgrp) ? mp->mp_procgrp : 0;

  /* If the exited process has a timer pending, kill it. */
  if (rmp->mp_flags & ALARM_ON) {
      set_alarm(rmp, (clock_t) 0);
  }

  /* Do accounting: fetch usage times and save with dead child process.
   * POSIX forbids accumulation at parent until child has been waited for.
   */
  if((r = sys_times(rmp->mp_endpoint, &user_time, &sys_time, NULL, NULL)) != OK)
  	panic("exit_proc: sys_times failed for endpoint %d: %d", rmp->mp_endpoint, r);
  rmp->mp_child_utime += user_time;		/* add user time */
  rmp->mp_child_stime += sys_time;		/* add system time */

  /* Critical system processes like INIT and VFS dying require special handling. */
  if (rmp->mp_endpoint == INIT_PROC_NR) {
	printf("PM: INIT died with exit status %d; showing stacktrace\n", exit_status);
	sys_diagctl_stacktrace(rmp->mp_endpoint);
	return; /* INIT dying usually leads to system shutdown. */
  }
  if (rmp->mp_endpoint == VFS_PROC_NR) {
	panic("exit_proc: VFS died with exit status %d", exit_status);
  }

  /* Clean up kernel state (stop process, notify VM). */
  exit_proc_cleanup_state(rmp);

  /* If privileged, destroy without waiting for VFS. */
  if (rmp->mp_flags & PRIV_PROC) {
	if((r = sys_clear(rmp->mp_endpoint)) != OK)
		panic("exit_proc: sys_clear failed for endpoint %d: %d", rmp->mp_endpoint, r);
  }

  /* Notify VFS and process event subscribers. */
  exit_proc_notify_vfs_events(rmp, dump_core);

  /* Clean up most of the flags describing the process's state before the exit,
   * and mark it as exiting.
   */
  rmp->mp_flags &= (IN_USE|VFS_CALL|PRIV_PROC|TRACE_EXIT|PROC_STOPPED);
  rmp->mp_flags |= EXITING;

  rmp->mp_exitstatus = (char) exit_status;

  /* For normal exits, try to notify the parent as soon as possible.
   * For core dumps, notify the parent only once the core dump has been made.
   */
  if (!dump_core)
	zombify(rmp);

  /* If the process has children, disinherit them. INIT is the new parent. */
  for (struct mproc *child_rmp = &mproc[0]; child_rmp < &mproc[NR_PROCS]; child_rmp++) {
	if (!(child_rmp->mp_flags & IN_USE)) continue;

	/* If this process was a tracer, the traced child needs to be handled. */
	if (child_rmp->mp_tracer == proc_nr) {
		tracer_died(child_rmp);
	}

	/* If this process was a parent, its children are disinherited to INIT. */
	if (child_rmp->mp_parent == proc_nr) {
		child_rmp->mp_parent = INIT_PROC_NR;

		/* If the child process is making a VFS call, remember that we set
		 * a new parent. This prevents FORK from replying to the wrong
		 * parent upon completion.
		 */
		if (child_rmp->mp_flags & VFS_CALL)
			child_rmp->mp_flags |= NEW_PARENT;

		/* Notify new parent (INIT). */
		if (child_rmp->mp_flags & ZOMBIE)
			check_parent(child_rmp, TRUE /*try_cleanup*/);
	}
  }

  /* Send a hangup to the process' process group if it was a session leader. */
  if (procgrp_of_session_leader != 0) {
      check_sig(-procgrp_of_session_leader, SIGHUP, FALSE /* ksig */);
  }
}

/*===========================================================================*
 *				exit_restart				     *
 *===========================================================================*/
void exit_restart(struct mproc *rmp)
{
/* VFS replied to our exit or coredump request. Perform the second half of the
 * exit code.
 */
  int r;

  if (rmp->mp_scheduler != NONE) { /* Kernel processes are KERNEL_SCHED_PROC */
      if((r = sched_stop(rmp->mp_scheduler, rmp->mp_endpoint)) != OK) {
          printf("PM: The scheduler did not want to give up "
                 "scheduling %s (endpoint %d), ret=%d.\n", rmp->mp_name, rmp->mp_endpoint, r);
      }
  }

  /* sched_stop is either called when the process is exiting or it is
   * being moved between schedulers. If it is being moved between
   * schedulers, we need to set the mp_scheduler to NONE so that PM
   * doesn't forward messages to the process' scheduler while being moved
   * (such as sched_nice). */
  rmp->mp_scheduler = NONE;

  /* For core dumps, now is the right time to try to contact the parent. */
  if (!(rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE | TOLD_PARENT)))
	zombify(rmp);

  if (!(rmp->mp_flags & PRIV_PROC))
  {
	/* destroy the (user) process */
	if((r = sys_clear(rmp->mp_endpoint)) != OK)
		panic("exit_restart: sys_clear failed for endpoint %d: %d", rmp->mp_endpoint, r);
  }

  /* Release the memory occupied by the child. */
  if((r = vm_exit(rmp->mp_endpoint)) != OK) {
  	panic("exit_restart: vm_exit failed for endpoint %d: %d", rmp->mp_endpoint, r);
  }

  if (rmp->mp_flags & TRACE_EXIT)
  {
	/* Wake up the tracer, completing the ptrace(T_EXIT) call */
	mproc[rmp->mp_tracer].mp_reply.m_pm_lc_ptrace.data = 0;
	reply(rmp->mp_tracer, OK);
  }

  /* Clean up if the parent has collected the exit status */
  if (rmp->mp_flags & TOLD_PARENT)
	cleanup(rmp);
}

/*===========================================================================*
 *				do_wait4				     *
 *===========================================================================*/
int
do_wait4(void)
{
/* A process wants to wait for a child to terminate. If a child is already
 * waiting, go clean it up and let this WAIT4 call terminate. Otherwise,
 * really wait.
 * A process calling WAIT4 never gets a reply in the usual way at the end
 * of the main loop (unless WNOHANG is set or no qualifying child exists).
 * If a child has already exited, the routine tell_parent() sends the reply
 * to awaken the caller.
 */
  register struct mproc *rp_child;
  vir_bytes addr_rusage;
  int i, pidarg, options, children_found, waited_for_child;
  struct mproc *current_mp = mp;

  /* Set internal variables. */
  pidarg  = m_in.m_lc_pm_wait4.pid;		/* 1st param */
  options = m_in.m_lc_pm_wait4.options;		/* 3rd param */
  addr_rusage = m_in.m_lc_pm_wait4.addr;		/* 4th param */
  if (pidarg == 0) pidarg = -current_mp->mp_procgrp;	/* pidarg < 0 ==> proc grp */

  /* Is there a child waiting to be collected? At this point, pidarg != 0:
   *	pidarg  >  0 means pidarg is pid of a specific process to wait for
   *	pidarg == -1 means wait for any child
   *	pidarg  < -1 means wait for any child whose process group = -pidarg
   */
  children_found = 0;
  for (rp_child = &mproc[0]; rp_child < &mproc[NR_PROCS]; rp_child++) {
	if ((rp_child->mp_flags & (IN_USE | TOLD_PARENT)) != IN_USE) continue;
	if (rp_child->mp_parent != who_p && rp_child->mp_tracer != who_p) continue;
	if (rp_child->mp_parent != who_p && (rp_child->mp_flags & ZOMBIE)) continue;

	/* The value of pidarg determines which children qualify. */
	if (pidarg  > 0 && pidarg != rp_child->mp_pid) continue;
	if (pidarg < -1 && -pidarg != rp_child->mp_procgrp) continue;

	children_found++;			/* this child is acceptable */

	if (rp_child->mp_tracer == who_p) {
		if (rp_child->mp_flags & TRACE_ZOMBIE) {
			/* Traced child meets the pid test and has exited. */
			tell_tracer(rp_child);
			check_parent(rp_child, TRUE /*try_cleanup*/);
			return(SUSPEND);
		}
		if (rp_child->mp_flags & TRACE_STOPPED) {
			/* This child meets the pid test and is being traced.
			 * Deliver a signal to the tracer, if any.
			 */
			for (i = 1; i < _NSIG; i++) {
				if (sigismember(&rp_child->mp_sigtrace, i)) {
					/* TODO: rusage support */
					sigdelset(&rp_child->mp_sigtrace, i);
					current_mp->mp_reply.m_pm_lc_wait4.status =
					    W_STOPCODE(i);
					return(rp_child->mp_pid);
				}
			}
		}
	}

	if (rp_child->mp_parent == who_p) {
		if (rp_child->mp_flags & ZOMBIE) {
			/* This child meets the pid test and has exited. */
			waited_for_child = tell_parent(rp_child, addr_rusage);

			if (waited_for_child &&
			    !(rp_child->mp_flags & (VFS_CALL | EVENT_CALL)))
				cleanup(rp_child);
			return(SUSPEND);
		}
	}
  }

  /* No qualifying child has exited. Wait for one, unless none exists. */
  if (children_found > 0) {
	/* At least 1 child meets the pid test exists, but has not exited. */
	if (options & WNOHANG) {
		return(0);    /* parent does not want to wait */
	}
	current_mp->mp_flags |= WAITING;	     /* parent wants to wait */
	current_mp->mp_wpid = (pid_t) pidarg;	     /* save pid for later */
	current_mp->mp_waddr = addr_rusage;		     /* save rusage addr for later */
	return(SUSPEND);		     /* do not reply, let it wait */
  } else {
	/* No child even meets the pid test. Return error immediately. */
	return(ECHILD);			     /* no - parent has no children */
  }
}

/*===========================================================================*
 *				wait_test				     *
 *===========================================================================*/
int
wait_test(
	struct mproc *rmp_parent,			/* process that may be waiting */
	struct mproc *child			/* process that may be waited for */
)
{
/* See if a parent or tracer process is waiting for a child process.
 * A tracer is considered to be a pseudo-parent.
 */
  int parent_waiting, right_child;
  pid_t pidarg;

  pidarg = rmp_parent->mp_wpid;		/* who's being waited for? */
  parent_waiting = rmp_parent->mp_flags & WAITING;
  right_child =				/* child meets one of the 3 tests? */
  	(pidarg == -1 || pidarg == child->mp_pid ||
  	 -pidarg == child->mp_procgrp);

  return (parent_waiting && right_child);
}

/*===========================================================================*
 *				zombify					     *
 *===========================================================================*/
static void
zombify(struct mproc *rmp_child)
{
/* Zombify a process. First check if the exiting process is traced by a process
 * other than its parent; if so, the tracer must be notified about the exit
 * first. Once that is done, the real parent may be notified about the exit of
 * its child.
 */
  struct mproc *t_mp;

  if (rmp_child->mp_flags & (TRACE_ZOMBIE | ZOMBIE))
	panic("zombify: process (pid %d) was already a zombie", rmp_child->mp_pid);

  /* See if we have to notify a tracer process first. */
  if (rmp_child->mp_tracer != NO_TRACER && rmp_child->mp_tracer != rmp_child->mp_parent) {
	rmp_child->mp_flags |= TRACE_ZOMBIE;

	t_mp = &mproc[rmp_child->mp_tracer];

	/* Do not bother sending SIGCHLD signals to tracers. */
	if (!wait_test(t_mp, rmp_child))
		return;

	tell_tracer(rmp_child);
  }
  else {
	rmp_child->mp_flags |= ZOMBIE;
  }

  /* No tracer, or tracer is parent, or tracer has now been notified. */
  check_parent(rmp_child, FALSE /*try_cleanup*/);
}

/*===========================================================================*
 *				check_parent				     *
 *===========================================================================*/
static void
check_parent(
	struct mproc *child,			/* tells which process is exiting */
	int try_cleanup			/* clean up the child when done? */
)
{
/* We would like to inform the parent of an exiting child about the child's
 * death. If the parent is waiting for the child, tell it immediately;
 * otherwise, send it a SIGCHLD signal.
 *
 * Note that we may call this function twice on a single child; first with
 * its original parent, later (if the parent died) with INIT as its parent.
 */
  struct mproc *p_mp;

  /* Validate parent index. If parent is INIT_PROC_NR, then mproc[INIT_PROC_NR] is PM_PROC_NR */
  if (child->mp_parent < 0 || child->mp_parent >= NR_PROCS) {
      panic("check_parent: child (pid %d) has invalid parent index %d", child->mp_pid, child->mp_parent);
  }
  p_mp = &mproc[child->mp_parent];

  if (p_mp->mp_flags & EXITING) {
	/* This may trigger if the child of a dead parent dies. The child will
	 * be assigned to INIT and rechecked shortly after. Do nothing.
	 */
  }
  else if (wait_test(p_mp, child)) {
	if (!tell_parent(child, p_mp->mp_waddr))
		try_cleanup = FALSE; /* copy error - child is still there */

	/* The 'try_cleanup' flag merely saves us from having to be really
	 * careful with statement ordering in exit_proc() and exit_restart().
	 */
	if (try_cleanup && !(child->mp_flags & (VFS_CALL | EVENT_CALL)))
		cleanup(child);
  }
  else {
	/* Parent is not waiting. */
	sig_proc(p_mp, SIGCHLD, TRUE /*trace*/, FALSE /* ksig */);
  }
}

/*===========================================================================*
 *				tell_parent				     *
 *===========================================================================*/
static int tell_parent(struct mproc *child, vir_bytes addr)
{
/* Tell the parent of the given process that it has terminated, by satisfying
 * the parent's ongoing wait4() call.  If the parent has requested the child
 * tree's resource usage, copy that information out first.  The copy may fail;
 * in that case, the parent's wait4() call will return with an error, but the
 * child will remain a zombie.  Return TRUE if the child is cleaned up, or
 * FALSE if the child is still a zombie.
 */
  struct rusage r_usage;
  int parent_slot_nr;
  struct mproc *parent;
  int r;

  parent_slot_nr = child->mp_parent;
  if (parent_slot_nr < 0 || parent_slot_nr >= NR_PROCS)
	panic("tell_parent: bad value in mp_parent: %d for child pid %d", parent_slot_nr, child->mp_pid);
  if(!(child->mp_flags & ZOMBIE))
  	panic("tell_parent: child pid %d not a zombie", child->mp_pid);
  if(child->mp_flags & TOLD_PARENT)
	panic("tell_parent: telling parent again for child pid %d", child->mp_pid);
  parent = &mproc[parent_slot_nr];

  /* See if we need to report resource usage to the parent. */
  if (addr) {
	/* We report only user and system times for now. TODO: support other
	 * fields, although this is tricky since the child process is already
	 * gone as far as the kernel and other services are concerned..
	 */
	memset(&r_usage, 0, sizeof(r_usage));
	set_rusage_times(&r_usage, child->mp_child_utime,
	    child->mp_child_stime);

	if ((r = sys_datacopy(SELF, (vir_bytes)&r_usage, parent->mp_endpoint,
	    addr, sizeof(r_usage))) != OK) {
		reply(parent_slot_nr, r);

		return FALSE; /* copy error - the child is still there */
	}
  }

  /* Wake up the parent by sending the reply message. */
  parent->mp_reply.m_pm_lc_wait4.status =
	W_EXITCODE(child->mp_exitstatus, child->mp_sigstatus);
  reply(parent_slot_nr, child->mp_pid);
  parent->mp_flags &= ~WAITING;		/* parent no longer waiting */
  child->mp_flags &= ~ZOMBIE;		/* child no longer a zombie */
  child->mp_flags |= TOLD_PARENT;	/* avoid informing parent twice */

  /* Now that the child has been waited for, accumulate the times of the
   * terminated child process at the parent.
   */
  parent->mp_child_utime += child->mp_child_utime;
  parent->mp_child_stime += child->mp_child_stime;

  return TRUE; /* child has been waited for */
}

/*===========================================================================*
 *				tell_tracer				     *
 *===========================================================================*/
static void
tell_tracer(
	struct mproc *child			/* tells which process is exiting */
)
{
  int tracer_slot_nr;
  struct mproc *tracer;

  tracer_slot_nr = child->mp_tracer;
  if (tracer_slot_nr < 0 || tracer_slot_nr >= NR_PROCS)
	panic("tell_tracer: bad value in mp_tracer: %d for child pid %d", tracer_slot_nr, child->mp_pid);
  if(!(child->mp_flags & TRACE_ZOMBIE))
  	panic("tell_tracer: child pid %d not a zombie for tracer", child->mp_pid);
  tracer = &mproc[tracer_slot_nr];

  /* TODO: rusage support for tracer */

  tracer->mp_reply.m_pm_lc_wait4.status =
	W_EXITCODE(child->mp_exitstatus, (child->mp_sigstatus & 0377));
  reply(tracer_slot_nr, child->mp_pid);
  tracer->mp_flags &= ~WAITING;		/* tracer no longer waiting */
  child->mp_flags &= ~TRACE_ZOMBIE;	/* child no longer zombie to tracer */
  child->mp_flags |= ZOMBIE;		/* child is now zombie to parent */
}

/*===========================================================================*
 *				tracer_died				     *
 *===========================================================================*/
static void
tracer_died(
	struct mproc *child			/* process being traced */
)
{
/* The process that was tracing the given child, has died for some reason.
 * This is really the tracer's fault, but we can't let INIT deal with this.
 */

  child->mp_tracer = NO_TRACER;
  child->mp_flags &= ~TRACE_EXIT;

  /* If the tracer died while the child was running or stopped, we have no
   * idea what state the child is in. Avoid a trainwreck, by killing the child.
   * Note that this may cause cascading exits.
   */
  if (!(child->mp_flags & EXITING)) {
	sig_proc(child, SIGKILL, TRUE /*trace*/, FALSE /* ksig */);

	return;
  }

  /* If the tracer died while the child was telling it about its own death,
   * forget about the tracer and notify the real parent instead.
   */
  if (child->mp_flags & TRACE_ZOMBIE) {
	child->mp_flags &= ~TRACE_ZOMBIE;
	child->mp_flags |= ZOMBIE;

	check_parent(child, TRUE /*try_cleanup*/);
  }
}

/*===========================================================================*
 *				cleanup					     *
 *===========================================================================*/
static void
cleanup(
	register struct mproc *rmp	/* tells which process is exiting */
)
{
  /* Release the process table entry and reinitialize some field. */
  if (rmp->mp_flags & IN_USE) {
      rmp->mp_pid = 0;
      rmp->mp_flags = 0; /* Clear all flags including IN_USE */
      rmp->mp_child_utime = 0;
      rmp->mp_child_stime = 0;
      procs_in_use--;
  }
}