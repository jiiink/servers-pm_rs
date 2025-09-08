/* This file contains the main program of the process manager and some related
 * procedures.  When MINIX starts up, the kernel runs for a little while,
 * initializing itself and its tasks, and then it runs PM and VFS.  Both PM
 * and VFS initialize themselves as far as they can. PM asks the kernel for
 * all free memory and starts serving requests.
 *
 * The entry points into this file are:
 *   main:	starts PM running
 *   reply:	send a reply to a process making a PM system call
 */

#include "pm.h"
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/ds.h>
#include <minix/endpoint.h>
#include <minix/minlib.h>
#include <minix/type.h>
#include <minix/vm.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <machine/archtypes.h>
#include <assert.h>
#include "mproc.h"

#include "kernel/const.h"
#include "kernel/config.h"
#include "kernel/proc.h"

#if ENABLE_SYSCALL_STATS
EXTERN unsigned long calls_stats[NR_PM_CALLS];
#endif

static int get_nice_value_from_queue(int queue);
static void handle_vfs_reply(void);
static void initialize_mproc_table(void);
static void load_boot_processes(struct boot_image *image);

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init_fresh(int type, sef_init_info_t *info);

/*===========================================================================*
 *				main					     *
 *===========================================================================*/
int
main(void)
{
/* Main routine of the process manager. */
  unsigned int call_index;
  int ipc_status, result;

  /* SEF local startup. */
  sef_local_startup();

  /* This is PM's main loop-  get work and do it, forever and forever. */
  while (TRUE) {
	/* Wait for the next message. */
	if (sef_receive_status(ANY, &m_in, &ipc_status) != OK)
		panic("PM sef_receive_status error");

	/* Check for system notifications first. Special cases. */
	if (is_ipc_notify(ipc_status)) {
		if (_ENDPOINT_P(m_in.m_source) == CLOCK) {
			expire_timers(m_in.m_notify.timestamp);
		}
		/* done, continue */
		continue;
	}

	/* Extract useful information from the message. */
	who_e = m_in.m_source;	/* who sent the message */
	if (pm_isokendpt(who_e, &who_p) != OK) {
		printf("PM: got message from invalid endpoint: %d (type %d)\n", who_e, m_in.m_type);
		result = EDEADSRCDST; /* Treat as if process is dead */
	} else {
		mp = &mproc[who_p];	/* process slot of caller */
		call_nr = m_in.m_type;	/* system call number */

		/* Drop delayed calls from exiting processes to prevent issues. */
		if (mp->mp_flags & EXITING) {
			continue;
		}

		/* Handle VFS replies and process event replies first. */
		if (IS_VFS_PM_RS(call_nr) && who_e == VFS_PROC_NR) {
			handle_vfs_reply();
			result = SUSPEND; /* VFS replies are handled asynchronously */
		} else if (call_nr == PROC_EVENT_REPLY) {
			result = do_proc_event_reply();
		} else if (IS_PM_CALL(call_nr)) {
			/* If the system call number is valid, perform the call. */
			call_index = (unsigned int) (call_nr - PM_BASE);

			if (call_index < NR_PM_CALLS && call_vec[call_index] != NULL) {
#if ENABLE_SYSCALL_STATS
				calls_stats[call_index]++;
#endif
				result = (*call_vec[call_index])();
			} else {
				printf("PM: unknown PM call_nr %d from %d (proc %d)\n", call_nr, who_e, who_p);
				result = ENOSYS;
			}
		} else {
			printf("PM: unknown call_nr %d from %d (proc %d)\n", call_nr, who_e, who_p);
			result = ENOSYS;
		}
	}

	/* Send reply if not suspended. */
	if (result != SUSPEND) reply(who_p, result);
  }
  return(OK);
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void
sef_local_startup(void)
{
  /* Register init callbacks. */
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL); /* Use default stateful restart */

  /* Register signal callbacks. */
  sef_setcb_signal_manager(process_ksig);

  /* Let SEF perform startup. */
  sef_startup();
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
/* Initialize the process manager. */
  int s;
  static struct boot_image image[NR_BOOT_PROCS];

  initialize_mproc_table();

  /* Obtain a copy of the boot monitor parameters. */
  if ((s = sys_getmonparams(monitor_params, sizeof(monitor_params))) != OK)
      panic("get monitor params failed: %d", s);

  /* Initialize PM's process table. Request a copy of the system image table
   * that is defined at the kernel level to see which slots to fill in.
   */
  if (OK != (s = sys_getimage(image)))
  	panic("couldn't get image table: %d", s);

  load_boot_processes(image);

  /* Tell VFS that no more system processes follow and synchronize. */
  message mess;
  memset(&mess, 0, sizeof(mess));
  mess.m_type = VFS_PM_INIT;
  mess.VFS_PM_ENDPT = NONE; /* Sentinel to indicate end of boot processes */
  if (ipc_sendrec(VFS_PROC_NR, &mess) != OK || mess.m_type != OK)
	panic("can't sync up with VFS");

  system_hz = sys_hz();

  /* Initialize user-space scheduling. */
  sched_init();

  printf("PM: Minix %s starting. Initializing tasks and system processes...\n", OS_RELEASE);

  return OK;
}

/*===========================================================================*
 *				initialize_mproc_table			     *
 *===========================================================================*/
static void initialize_mproc_table(void)
{
  register struct mproc *rmp;
  static char core_sigs[] = { SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
				SIGEMT, SIGFPE, SIGBUS, SIGSEGV };
  static char ign_sigs[] = { SIGCHLD, SIGWINCH, SIGCONT, SIGINFO };
  static char noign_sigs[] = { SIGILL, SIGTRAP, SIGEMT, SIGFPE,
				SIGBUS, SIGSEGV };
  register char *sig_ptr;

  for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
	init_timer(&rmp->mp_timer);
	rmp->mp_magic = MP_MAGIC;
	rmp->mp_sigact = mpsigact[rmp - mproc];
	rmp->mp_eventsub = NO_EVENTSUB;
    rmp->mp_endpoint = NONE; /* Indicate slot is not in use yet */
  }

  /* Build the set of signals which cause core dumps, and the set of signals
   * that are by default ignored.
   */
  sigemptyset(&core_sset);
  for (sig_ptr = core_sigs; sig_ptr < core_sigs+sizeof(core_sigs); sig_ptr++)
	sigaddset(&core_sset, *sig_ptr);
  sigemptyset(&ign_sset);
  for (sig_ptr = ign_sigs; sig_ptr < ign_sigs+sizeof(ign_sigs); sig_ptr++)
	sigaddset(&ign_sset, *sig_ptr);
  sigemptyset(&noign_sset);
  for (sig_ptr = noign_sigs; sig_ptr < noign_sigs+sizeof(noign_sigs); sig_ptr++)
	sigaddset(&noign_sset, *sig_ptr);
}

/*===========================================================================*
 *				load_boot_processes			     *
 *===========================================================================*/
static void load_boot_processes(struct boot_image *image)
{
  register struct boot_image *ip;
  register struct mproc *rmp;
  message mess;
  int s;

  procs_in_use = 0;				/* start populating table */
  for (ip = &image[0]; ip < &image[NR_BOOT_PROCS]; ip++) {
  	if (ip->proc_nr >= 0) {			/* task have negative nrs */
  		procs_in_use += 1;		/* found user process */

		/* Set process details found in the image table. */
		rmp = &mproc[ip->proc_nr];
  		(void)strlcpy(rmp->mp_name, ip->proc_name, sizeof(rmp->mp_name));
  		(void) sigemptyset(&rmp->mp_ignore);
  		(void) sigemptyset(&rmp->mp_sigmask);
  		(void) sigemptyset(&rmp->mp_catch);
		rmp->mp_flags |= IN_USE;

		if (ip->proc_nr == INIT_PROC_NR) {	/* user process (INIT) */
  			/* INIT is root, we make it father of itself. This is
  			 * not really OK, INIT should have no father, i.e.
  			 * a father with pid NO_PID. But PM currently assumes
  			 * that mp_parent always points to a valid slot number.
  			 */
  			rmp->mp_parent = INIT_PROC_NR;
  			rmp->mp_procgrp = rmp->mp_pid = INIT_PID;

			/* Set scheduling info */
			rmp->mp_scheduler = KERNEL; /* Scheduled by kernel */
			rmp->mp_nice = get_nice_value_from_queue(USR_Q);
		}
		else {					/* system process */
			rmp->mp_flags |= PRIV_PROC;
			if(ip->proc_nr == RS_PROC_NR) {
  				rmp->mp_parent = INIT_PROC_NR; /* RS is parented by INIT */
  			}
  			else {
  				rmp->mp_parent = RS_PROC_NR; /* Other system processes parented by RS */
  			}
  			rmp->mp_pid = get_free_pid(); /* Assign a unique PID */

			/* RS schedules this process, unless it's kernel-scheduled */
			rmp->mp_scheduler = NONE; /* Placeholder, RS will set actual scheduler */
			rmp->mp_nice = get_nice_value_from_queue(SRV_Q);
		}

		/* Get kernel endpoint identifier. */
		rmp->mp_endpoint = ip->endpoint;

		/* Tell VFS about this system process. */
		memset(&mess, 0, sizeof(mess));
		mess.m_type = VFS_PM_INIT;
		mess.VFS_PM_SLOT = ip->proc_nr;
		mess.VFS_PM_PID = rmp->mp_pid;
		mess.VFS_PM_ENDPT = rmp->mp_endpoint;
  		if (OK != (s = ipc_send(VFS_PROC_NR, &mess)))
			panic("can't sync up with VFS: %d", s);
  	}
  }
}

/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
void
reply(
	int proc_nr,			/* process to reply to (mproc slot index) */
	int result			/* result of call (usually OK or error #) */
)
{
/* Send a reply to a user process. System calls may occasionally fill in other
 * fields, this is only for the main return value and for sending the reply.
 */
  struct mproc *rmp_target;
  int r;

  if(proc_nr < 0 || proc_nr >= NR_PROCS)
      panic("reply arg out of range: %d", proc_nr);

  rmp_target = &mproc[proc_nr];
  rmp_target->mp_reply.m_type = result;

  if ((r = ipc_sendnb(rmp_target->mp_endpoint, &rmp_target->mp_reply)) != OK) {
	/* Log the error, but can't really recover if we can't reply. */
	printf("PM can't reply to %d (%s): %d\n", rmp_target->mp_endpoint,
		rmp_target->mp_name, r);
  }
}

/*===========================================================================*
 *				get_nice_value_from_queue		     *
 *===========================================================================*/
static int
get_nice_value_from_queue(
	int queue				/* scheduling queue (e.g., USR_Q, SRV_Q) */
)
{
/* Processes in the boot image have a priority assigned (implicitly via queue).
 * The PM doesn't know about priorities directly, but uses 'nice' values
 * instead. The queue ranges from MIN_USER_Q to MAX_USER_Q. We map this
 * to PRIO_MIN to PRIO_MAX.
 */
  int nice_val = (queue - USER_Q) * (PRIO_MAX - PRIO_MIN + 1) /
      (MIN_USER_Q - MAX_USER_Q + 1);

  /* Ensure nice_val stays within the valid range. */
  if (nice_val > PRIO_MAX) nice_val = PRIO_MAX;
  if (nice_val < PRIO_MIN) nice_val = PRIO_MIN;
  return nice_val;
}

/*===========================================================================*
 *				handle_vfs_reply       			     *
 *===========================================================================*/
static void
handle_vfs_reply(void)
{
  struct mproc *rmp;
  endpoint_t proc_e;
  int r, proc_n;
  int new_parent_flag; /* Renamed from 'new_parent' to avoid confusion with parent_proc_nr */

  /* VFS_PM_REBOOT is the only request not associated with a process.
   * Handle its reply first.
   */
  if (call_nr == VFS_PM_REBOOT_REPLY) {
	/* Ask the kernel to abort. All system services, including
	 * the PM, will get a HARD_STOP notification. Await the
	 * notification in the main loop.
	 */
	sys_abort(abort_flag);
	return;
  }

  /* Get the process associated with this call. */
  proc_e = m_in.VFS_PM_ENDPT;

  if (pm_isokendpt(proc_e, &proc_n) != OK) {
	panic("handle_vfs_reply: got bad endpoint from VFS: %d for call %d", proc_e, call_nr);
  }

  rmp = &mproc[proc_n];

  /* Now that VFS replied, mark the process as VFS-idle again. */
  if (!(rmp->mp_flags & VFS_CALL))
	panic("handle_vfs_reply: reply %d from VFS for endpoint %d without an active request", call_nr, proc_e);

  new_parent_flag = rmp->mp_flags & NEW_PARENT;
  rmp->mp_flags &= ~(VFS_CALL | NEW_PARENT);

  if (rmp->mp_flags & UNPAUSED)
  	panic("handle_vfs_reply: UNPAUSED set on entry for endpoint %d, call %d", proc_e, call_nr);

  /* Call-specific handler code. */
  switch (call_nr) {
  case VFS_PM_SETUID_REPLY:
  case VFS_PM_SETGID_REPLY:
  case VFS_PM_SETGROUPS_REPLY:
	/* Wake up the original caller. */
	reply(proc_n, OK);
	break;

  case VFS_PM_SETSID_REPLY:
	/* Wake up the original caller with its new process group ID. */
	reply(proc_n, rmp->mp_procgrp);
	break;

  case VFS_PM_EXEC_REPLY:
	exec_restart(rmp, m_in.VFS_PM_STATUS, (vir_bytes)m_in.VFS_PM_PC,
		(vir_bytes)m_in.VFS_PM_NEWSP,
		(vir_bytes)m_in.VFS_PM_NEWPS_STR);
	break;

  case VFS_PM_CORE_REPLY:
	if (m_in.VFS_PM_STATUS == OK)
		rmp->mp_sigstatus |= WCOREFLAG; /* Mark that core file was dumped */
	/* FALLTHROUGH */
  case VFS_PM_EXIT_REPLY:
	assert(rmp->mp_flags & EXITING);

	/* Publish the exit event. Continue exiting the process after that. */
	publish_event(rmp);
	return; /* Do not take the default action, handled by publish_event -> exit_restart */

  case VFS_PM_FORK_REPLY:
	/* Schedule the newly created process. */
	r = OK;
	if (!(rmp->mp_flags & PRIV_PROC) && rmp->mp_scheduler != NONE) { /* Only user processes are scheduled by a userland scheduler */
		r = sched_start_user(rmp->mp_scheduler, rmp);
	} else if (rmp->mp_flags & PRIV_PROC && rmp->mp_scheduler == SCHED_PROC_NR) {
		/* System processes managed by RS are initially NONE, but if forked by
		 * a non-RS privileged process or explicitly managed by SCHED_PROC_NR,
		 * they need to be started by PM. This branch might be unnecessary
		 * if all privileged process forks are handled by RS or KERNEL. */
		r = sched_start_user(rmp->mp_scheduler, rmp);
	}

	/* If scheduling the process failed, tear down and fail the fork. */
	if (r != OK) {
		rmp->mp_scheduler = NONE; /* Prevent further scheduling attempts */
		exit_proc(rmp, -1, FALSE /*dump_core*/); /* Terminate the child */

		/* Wake up the parent with a failed fork (unless parent is already dead). */
		if (!new_parent_flag) {
			reply(rmp->mp_parent, -1);
		}
	} else {
		/* Wake up the child process. */
		reply(proc_n, OK);

		/* Wake up the parent, unless the parent is already dead. */
		if (!new_parent_flag) {
			reply(rmp->mp_parent, rmp->mp_pid);
		}
	}
	break;

  case VFS_PM_SRV_FORK_REPLY:
	/* For srv_fork, PM already replied to the child. No further action needed here. */
	break;

  case VFS_PM_UNPAUSE_REPLY:
	/* The target process must always be stopped while unpausing; otherwise
	 * it could just end up pausing itself on a new call afterwards.
	 */
	assert(rmp->mp_flags & PROC_STOPPED);

	/* Process is now unpaused. */
	rmp->mp_flags |= UNPAUSED;

	/* Publish the signal event. Continue with signals only after that. */
	publish_event(rmp);
	return; /* Do not take the default action, handled by publish_event -> restart_sigs */

  default:
	panic("handle_vfs_reply: unknown reply code: %d from VFS endpoint %d", call_nr, proc_e);
  }

  /* Now that the process is idle again, look at pending signals. */
  if ((rmp->mp_flags & (IN_USE | EXITING)) == IN_USE) {
	  restart_sigs(rmp);
  }
}