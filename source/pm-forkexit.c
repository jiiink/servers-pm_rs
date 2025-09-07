/* This file deals with creating processes (via FORK) and deleting them (via
 * EXIT/WAIT4).
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

#define LAST_FEW 2	/* last few slots reserved for superuser */

/* Function prototypes */
static void zombify(struct mproc *rmp);
static void check_parent(struct mproc *child, int try_cleanup);
static int tell_parent(struct mproc *child, vir_bytes addr);
static void tell_tracer(struct mproc *child);
static void tracer_died(struct mproc *child);
static void cleanup(struct mproc *rmp);
static int find_free_slot(void);
static int allocate_child_slot(void);
static void init_child_process(struct mproc *parent, struct mproc *child, 
                               int child_slot, endpoint_t child_ep);
static void prepare_vfs_fork_message(message *m, struct mproc *parent, 
                                     struct mproc *child);

/*===========================================================================*
 *				find_free_slot				     *
 *===========================================================================*/
static int find_free_slot(void)
{
	static unsigned int next_child = 0;
	int n = 0;

	do {
		next_child = (next_child + 1) % NR_PROCS;
		n++;
	} while ((mproc[next_child].mp_flags & IN_USE) && n <= NR_PROCS);

	if (n > NR_PROCS) {
		return -1;
	}

	return (int)next_child;
}

/*===========================================================================*
 *				allocate_child_slot			     *
 *===========================================================================*/
static int allocate_child_slot(void)
{
	struct mproc *rmp = mp;

	/* Check if tables are full */
	if (procs_in_use == NR_PROCS) {
		printf("PM: warning, process table is full!\n");
		return EAGAIN;
	}

	/* Check if non-root user would fill last slots */
	if (procs_in_use >= NR_PROCS - LAST_FEW && rmp->mp_effuid != 0) {
		printf("PM: warning, process table is nearly full!\n");
		return EAGAIN;
	}

	/* Find free slot */
	int slot = find_free_slot();
	if (slot < 0) {
		panic("do_fork can't find child slot");
	}

	return slot;
}

/*===========================================================================*
 *				init_child_process			     *
 *===========================================================================*/
static void init_child_process(struct mproc *parent, struct mproc *child,
                               int child_slot, endpoint_t child_ep)
{
	int i;

	if (parent == NULL || child == NULL) {
		return;
	}

	/* Copy parent's process slot to child */
	*child = *parent;
	child->mp_sigact = mpsigact[child_slot];
	memcpy(child->mp_sigact, parent->mp_sigact, sizeof(mpsigact[child_slot]));

	/* Set child-specific fields */
	child->mp_parent = parent - mproc;
	child->mp_endpoint = child_ep;

	/* Handle tracing */
	if (!(child->mp_trace_flags & TO_TRACEFORK)) {
		child->mp_tracer = NO_TRACER;
		child->mp_trace_flags = 0;
		(void)sigemptyset(&child->mp_sigtrace);
	}

	/* Handle scheduling for system processes */
	if (child->mp_flags & PRIV_PROC) {
		assert(child->mp_scheduler == NONE);
		child->mp_scheduler = SCHED_PROC_NR;
	}

	/* Inherit only specific flags */
	child->mp_flags &= (IN_USE | DELAY_CALL | TAINTED);

	/* Reset administrative fields */
	child->mp_child_utime = 0;
	child->mp_child_stime = 0;
	child->mp_exitstatus = 0;
	child->mp_sigstatus = 0;
	child->mp_started = getticks();

	/* Reset timers */
	for (i = 0; i < NR_ITIMERS; i++) {
		child->mp_interval[i] = 0;
	}

	assert(child->mp_eventsub == NO_EVENTSUB);
}

/*===========================================================================*
 *				prepare_vfs_fork_message		     *
 *===========================================================================*/
static void prepare_vfs_fork_message(message *m, struct mproc *parent,
                                     struct mproc *child)
{
	if (m == NULL || parent == NULL || child == NULL) {
		return;
	}

	memset(m, 0, sizeof(*m));
	m->m_type = VFS_PM_FORK;
	m->VFS_PM_ENDPT = child->mp_endpoint;
	m->VFS_PM_PENDPT = parent->mp_endpoint;
	m->VFS_PM_CPID = child->mp_pid;
	m->VFS_PM_REUID = -1;
	m->VFS_PM_REGID = -1;
}

/*===========================================================================*
 *				do_fork					     *
 *===========================================================================*/
int do_fork(void)
{
	struct mproc *rmp = mp;
	struct mproc *rmc;
	pid_t new_pid;
	int child_slot;
	endpoint_t child_ep;
	message m;
	int s;

	/* Allocate slot for child */
	child_slot = allocate_child_slot();
	if (child_slot < 0 || child_slot == EAGAIN) {
		return child_slot;
	}

	/* Fork memory */
	s = vm_fork(rmp->mp_endpoint, child_slot, &child_ep);
	if (s != OK) {
		return s;
	}

	/* Initialize child process */
	rmc = &mproc[child_slot];
	procs_in_use++;
	init_child_process(rmp, rmc, child_slot, child_ep);

	/* Assign PID */
	new_pid = get_free_pid();
	rmc->mp_pid = new_pid;

	/* Notify VFS */
	prepare_vfs_fork_message(&m, rmp, rmc);
	tell_vfs(rmc, &m);

	/* Notify tracer if present */
	if (rmc->mp_tracer != NO_TRACER) {
		sig_proc(rmc, SIGSTOP, TRUE, FALSE);
	}

	return SUSPEND;
}

/*===========================================================================*
 *				do_srv_fork				     *
 *===========================================================================*/
int do_srv_fork(void)
{
	struct mproc *rmp = mp;
	struct mproc *rmc;
	pid_t new_pid;
	int child_slot;
	endpoint_t child_ep;
	message m;
	int s, i;

	/* Only RS can use srv_fork */
	if (mp->mp_endpoint != RS_PROC_NR) {
		return EPERM;
	}

	/* Allocate slot for child */
	child_slot = allocate_child_slot();
	if (child_slot < 0 || child_slot == EAGAIN) {
		return child_slot;
	}

	/* Fork memory */
	s = vm_fork(rmp->mp_endpoint, child_slot, &child_ep);
	if (s != OK) {
		return s;
	}

	/* Initialize child process */
	rmc = &mproc[child_slot];
	procs_in_use++;
	*rmc = *rmp;
	rmc->mp_sigact = mpsigact[child_slot];
	memcpy(rmc->mp_sigact, rmp->mp_sigact, sizeof(mpsigact[child_slot]));
	
	rmc->mp_parent = who_p;
	rmc->mp_endpoint = child_ep;

	/* Handle tracing */
	if (!(rmc->mp_trace_flags & TO_TRACEFORK)) {
		rmc->mp_tracer = NO_TRACER;
		rmc->mp_trace_flags = 0;
		(void)sigemptyset(&rmc->mp_sigtrace);
	}

	/* Set service-specific fields */
	rmc->mp_flags &= (IN_USE | PRIV_PROC | DELAY_CALL);
	rmc->mp_child_utime = 0;
	rmc->mp_child_stime = 0;
	rmc->mp_exitstatus = 0;
	rmc->mp_sigstatus = 0;
	rmc->mp_started = getticks();

	/* Set UIDs and GIDs from request */
	rmc->mp_realuid = m_in.m_lsys_pm_srv_fork.uid;
	rmc->mp_effuid = m_in.m_lsys_pm_srv_fork.uid;
	rmc->mp_svuid = m_in.m_lsys_pm_srv_fork.uid;
	rmc->mp_realgid = m_in.m_lsys_pm_srv_fork.gid;
	rmc->mp_effgid = m_in.m_lsys_pm_srv_fork.gid;
	rmc->mp_svgid = m_in.m_lsys_pm_srv_fork.gid;

	/* Reset timers */
	for (i = 0; i < NR_ITIMERS; i++) {
		rmc->mp_interval[i] = 0;
	}

	assert(rmc->mp_eventsub == NO_EVENTSUB);

	/* Assign PID */
	new_pid = get_free_pid();
	rmc->mp_pid = new_pid;

	/* Notify VFS */
	memset(&m, 0, sizeof(m));
	m.m_type = VFS_PM_SRV_FORK;
	m.VFS_PM_ENDPT = rmc->mp_endpoint;
	m.VFS_PM_PENDPT = rmp->mp_endpoint;
	m.VFS_PM_CPID = rmc->mp_pid;
	m.VFS_PM_REUID = m_in.m_lsys_pm_srv_fork.uid;
	m.VFS_PM_REGID = m_in.m_lsys_pm_srv_fork.gid;

	tell_vfs(rmc, &m);

	/* Notify tracer if present */
	if (rmc->mp_tracer != NO_TRACER) {
		sig_proc(rmc, SIGSTOP, TRUE, FALSE);
	}

	/* Wake up new process */
	reply(rmc - mproc, OK);

	return rmc->mp_pid;
}

/*===========================================================================*
 *				do_exit					     *
 *===========================================================================*/
int do_exit(void)
{
	/* System processes should not use PM's exit */
	if (mp->mp_flags & PRIV_PROC) {
		printf("PM: system process %d (%s) tries to exit(), sending SIGKILL\n",
		       mp->mp_endpoint, mp->mp_name);
		sys_kill(mp->mp_endpoint, SIGKILL);
	} else {
		exit_proc(mp, m_in.m_lc_pm_exit.status, FALSE);
	}
	return SUSPEND;
}

/*===========================================================================*
 *				exit_proc				     *
 *===========================================================================*/
void exit_proc(struct mproc *rmp, int exit_status, int dump_core)
{
	int proc_nr, proc_nr_e;
	int r;
	pid_t procgrp;
	clock_t user_time, sys_time;
	message m;
	struct mproc *child;

	if (rmp == NULL) {
		return;
	}

	/* Disable core dumps for setuid programs */
	if (dump_core && rmp->mp_realuid != rmp->mp_effuid) {
		dump_core = FALSE;
	}

	/* Disable core dumps for system processes */
	if (dump_core && (rmp->mp_flags & PRIV_PROC)) {
		dump_core = FALSE;
	}

	proc_nr = (int)(rmp - mproc);
	proc_nr_e = rmp->mp_endpoint;

	/* Remember session leader's process group */
	procgrp = (rmp->mp_pid == rmp->mp_procgrp) ? rmp->mp_procgrp : 0;

	/* Cancel pending alarms */
	if (rmp->mp_flags & ALARM_ON) {
		set_alarm(rmp, (clock_t)0);
	}

	/* Do accounting */
	r = sys_times(proc_nr_e, &user_time, &sys_time, NULL, NULL);
	if (r != OK) {
		panic("exit_proc: sys_times failed: %d", r);
	}
	rmp->mp_child_utime += user_time;
	rmp->mp_child_stime += sys_time;

	/* Stop the process */
	if (!(rmp->mp_flags & PROC_STOPPED)) {
		r = sys_stop(proc_nr_e);
		if (r != OK) {
			panic("sys_stop failed: %d", r);
		}
		rmp->mp_flags |= PROC_STOPPED;
	}

	/* Notify VM */
	r = vm_willexit(proc_nr_e);
	if (r != OK) {
		panic("exit_proc: vm_willexit failed: %d", r);
	}

	/* Handle special processes */
	if (proc_nr_e == INIT_PROC_NR) {
		printf("PM: INIT died with exit status %d; showing stacktrace\n", 
		       exit_status);
		sys_diagctl_stacktrace(proc_nr_e);
		return;
	}
	if (proc_nr_e == VFS_PROC_NR) {
		panic("exit_proc: VFS died: %d", r);
	}

	/* Tell VFS about exit */
	memset(&m, 0, sizeof(m));
	m.m_type = dump_core ? VFS_PM_DUMPCORE : VFS_PM_EXIT;
	m.VFS_PM_ENDPT = rmp->mp_endpoint;

	if (dump_core) {
		m.VFS_PM_TERM_SIG = rmp->mp_sigstatus;
		m.VFS_PM_PATH = rmp->mp_name;
	}

	tell_vfs(rmp, &m);

	/* Clean up system processes immediately */
	if (rmp->mp_flags & PRIV_PROC) {
		r = sys_clear(rmp->mp_endpoint);
		if (r != OK) {
			panic("exit_proc: sys_clear failed: %d", r);
		}
	}

	/* Update flags */
	rmp->mp_flags &= (IN_USE | VFS_CALL | PRIV_PROC | TRACE_EXIT | PROC_STOPPED);
	rmp->mp_flags |= EXITING;
	rmp->mp_exitstatus = (char)exit_status;

	/* Zombify if not dumping core */
	if (!dump_core) {
		zombify(rmp);
	}

	/* Disinherit children */
	for (child = &mproc[0]; child < &mproc[NR_PROCS]; child++) {
		if (!(child->mp_flags & IN_USE)) {
			continue;
		}

		/* Handle tracer death */
		if (child->mp_tracer == proc_nr) {
			tracer_died(child);
		}

		/* Reparent to INIT */
		if (child->mp_parent == proc_nr) {
			child->mp_parent = INIT_PROC_NR;

			if (child->mp_flags & VFS_CALL) {
				child->mp_flags |= NEW_PARENT;
			}

			if (child->mp_flags & ZOMBIE) {
				check_parent(child, TRUE);
			}
		}
	}

	/* Send SIGHUP to process group if session leader */
	if (procgrp != 0) {
		check_sig(-procgrp, SIGHUP, FALSE);
	}
}

/*===========================================================================*
 *				exit_restart				     *
 *===========================================================================*/
void exit_restart(struct mproc *rmp)
{
	int r;

	if (rmp == NULL) {
		return;
	}

	/* Stop scheduling */
	r = sched_stop(rmp->mp_scheduler, rmp->mp_endpoint);
	if (r != OK) {
		printf("PM: The scheduler did not want to give up "
		       "scheduling %s, ret=%d.\n", rmp->mp_name, r);
	}

	rmp->mp_scheduler = NONE;

	/* Zombify if needed */
	if (!(rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE | TOLD_PARENT))) {
		zombify(rmp);
	}

	/* Clear process for non-system processes */
	if (!(rmp->mp_flags & PRIV_PROC)) {
		r = sys_clear(rmp->mp_endpoint);
		if (r != OK) {
			panic("exit_restart: sys_clear failed: %d", r);
		}
	}

	/* Release memory */
	r = vm_exit(rmp->mp_endpoint);
	if (r != OK) {
		panic("exit_restart: vm_exit failed: %d", r);
	}

	/* Wake up tracer if needed */
	if (rmp->mp_flags & TRACE_EXIT) {
		mproc[rmp->mp_tracer].mp_reply.m_pm_lc_ptrace.data = 0;
		reply(rmp->mp_tracer, OK);
	}

	/* Clean up if parent has collected */
	if (rmp->mp_flags & TOLD_PARENT) {
		cleanup(rmp);
	}
}

/*===========================================================================*
 *				do_wait4				     *
 *===========================================================================*/
int do_wait4(void)
{
	struct mproc *rp;
	vir_bytes addr;
	int i, pidarg, options, children, waited_for;

	/* Get parameters */
	pidarg = m_in.m_lc_pm_wait4.pid;
	options = m_in.m_lc_pm_wait4.options;
	addr = m_in.m_lc_pm_wait4.addr;

	/* Convert pid 0 to process group */
	if (pidarg == 0) {
		pidarg = -mp->mp_procgrp;
	}

	/* Find qualifying children */
	children = 0;
	for (rp = &mproc[0]; rp < &mproc[NR_PROCS]; rp++) {
		/* Skip unused entries */
		if ((rp->mp_flags & (IN_USE | TOLD_PARENT)) != IN_USE) {
			continue;
		}

		/* Check relationship */
		if (rp->mp_parent != who_p && rp->mp_tracer != who_p) {
			continue;
		}
		if (rp->mp_parent != who_p && (rp->mp_flags & ZOMBIE)) {
			continue;
		}

		/* Check PID match */
		if (pidarg > 0 && pidarg != rp->mp_pid) {
			continue;
		}
		if (pidarg < -1 && -pidarg != rp->mp_procgrp) {
			continue;
		}

		children++;

		/* Check for traced child */
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
						mp->mp_reply.m_pm_lc_wait4.status = 
							W_STOPCODE(i);
						return rp->mp_pid;
					}
				}
			}
		}

		/* Check for zombie child */
		if (rp->mp_parent == who_p && (rp->mp_flags & ZOMBIE)) {
			waited_for = tell_parent(rp, addr);

			if (waited_for && 
			    !(rp->mp_flags & (VFS_CALL | EVENT_CALL))) {
				cleanup(rp);
			}
			return SUSPEND;
		}
	}

	/* Handle no children or WNOHANG */
	if (children == 0) {
		return ECHILD;
	}

	if (options & WNOHANG) {
		return 0;
	}

	/* Wait for child */
	mp->mp_flags |= WAITING;
	mp->mp_wpid = (pid_t)pidarg;
	mp->mp_waddr = addr;
	return SUSPEND;
}

/*===========================================================================*
 *				wait_test				     *
 *===========================================================================*/
int wait_test(struct mproc *rmp, struct mproc *child)
{
	int parent_waiting, right_child;
	pid_t pidarg;

	if (rmp == NULL || child == NULL) {
		return 0;
	}

	pidarg = rmp->mp_wpid;
	parent_waiting = rmp->mp_flags & WAITING;
	right_child = (pidarg == -1 || pidarg == child->mp_pid ||
	               -pidarg == child->mp_procgrp);

	return (parent_waiting && right_child);
}

/*===========================================================================*
 *				zombify					     *
 *===========================================================================*/
static void zombify(struct mproc *rmp)
{
	struct mproc *t_mp;

	if (rmp == NULL) {
		return;
	}

	if (rmp->mp_flags & (TRACE_ZOMBIE | ZOMBIE)) {
		panic("zombify: process was already a zombie");
	}

	/* Check for tracer */
	if (rmp->mp_tracer != NO_TRACER && rmp->mp_tracer != rmp->mp_parent) {
		rmp->mp_flags |= TRACE_ZOMBIE;

		t_mp = &mproc[rmp->mp_tracer];

		if (wait_test(t_mp, rmp)) {
			tell_tracer(rmp);
		}
	} else {
		rmp->mp_flags |= ZOMBIE;
	}

	check_parent(rmp, FALSE);
}

/*===========================================================================*
 *				check_parent				     *
 *===========================================================================*/
static void check_parent(struct mproc *child, int try_cleanup)
{
	struct mproc *p_mp;

	if (child == NULL) {
		return;
	}

	p_mp = &mproc[child->mp_parent];

	if (p_mp->mp_flags & EXITING) {
		return;
	}

	if (wait_test(p_mp, child)) {
		if (!tell_parent(child, p_mp->mp_waddr)) {
			try_cleanup = FALSE;
		}

		if (try_cleanup && !(child->mp_flags & (VFS_CALL | EVENT_CALL))) {
			cleanup(child);
		}
	} else {
		sig_proc(p_mp, SIGCHLD, TRUE, FALSE);
	}
}

/*===========================================================================*
 *				tell_parent				     *
 *===========================================================================*/
static int tell_parent(struct mproc *child, vir_bytes addr)
{
	struct rusage r_usage;
	int mp_parent;
	struct mproc *parent;
	int r;

	if (child == NULL) {
		return FALSE;
	}

	mp_parent = child->mp_parent;
	if (mp_parent <= 0) {
		panic("tell_parent: bad value in mp_parent: %d", mp_parent);
	}

	if (!(child->mp_flags & ZOMBIE)) {
		panic("tell_parent: child not a zombie");
	}

	if (child->mp_flags & TOLD_PARENT) {
		panic("tell_parent: telling parent again");
	}

	parent = &mproc[mp_parent];

	/* Copy resource usage if requested */
	if (addr) {
		memset(&r_usage, 0, sizeof(r_usage));
		set_rusage_times(&r_usage, child->mp_child_utime,
		                 child->mp_child_stime);

		r = sys_datacopy(SELF, (vir_bytes)&r_usage, parent->mp_endpoint,
		                 addr, sizeof(r_usage));
		if (r != OK) {
			reply(child->mp_parent, r);
			return FALSE;
		}
	}

	/* Send reply to parent */
	parent->mp_reply.m_pm_lc_wait4.status =
		W_EXITCODE(child->mp_exitstatus, child->mp_sigstatus);
	reply(child->mp_parent, child->mp_pid);
	parent->mp_flags &= ~WAITING;
	child->mp_flags &= ~ZOMBIE;
	child->mp_flags |= TOLD_PARENT;

	/* Accumulate child times */
	parent->mp_child_utime += child->mp_child_utime;
	parent->mp_child_stime += child->mp_child_stime;

	return TRUE;
}

/*===========================================================================*
 *				tell_tracer				     *
 *===========================================================================*/
static void tell_tracer(struct mproc *child)
{
	int mp_tracer;
	struct mproc *tracer;

	if (child == NULL) {
		return;
	}

	mp_tracer = child->mp_tracer;
	if (mp_tracer <= 0) {
		panic("tell_tracer: bad value in mp_tracer: %d", mp_tracer);
	}

	if (!(child->mp_flags & TRACE_ZOMBIE)) {
		panic("tell_tracer: child not a zombie");
	}

	tracer = &mproc[mp_tracer];

	tracer->mp_reply.m_pm_lc_wait4.status =
		W_EXITCODE(child->mp_exitstatus, (child->mp_sigstatus & 0377));
	reply(child->mp_tracer, child->mp_pid);
	tracer->mp_flags &= ~WAITING;
	child->mp_flags &= ~TRACE_ZOMBIE;
	child->mp_flags |= ZOMBIE;
}

/*===========================================================================*
 *				tracer_died				     *
 *===========================================================================*/
static void tracer_died(struct mproc *child)
{
	if (child == NULL) {
		return;
	}

	child->mp_tracer = NO_TRACER;
	child->mp_flags &= ~TRACE_EXIT;

	/* Kill orphaned traced process */
	if (!(child->mp_flags & EXITING)) {
		sig_proc(child, SIGKILL, TRUE, FALSE);
		return;
	}

	/* Convert trace zombie to regular zombie */
	if (child->mp_flags & TRACE_ZOMBIE) {
		child->mp_flags &= ~TRACE_ZOMBIE;
		child->mp_flags |= ZOMBIE;
		check_parent(child, TRUE);
	}
}

/*===========================================================================*
 *				cleanup					     *
 *===========================================================================*/
static void cleanup(struct mproc *rmp)
{
	if (rmp == NULL) {
		return;
	}

	/* Reset process slot */
	rmp->mp_pid = 0;
	rmp->mp_flags = 0;
	rmp->mp_child_utime = 0;
	rmp->mp_child_stime = 0;
	procs_in_use--;
}