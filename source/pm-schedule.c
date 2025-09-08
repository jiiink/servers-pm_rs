#include "pm.h"
#include <assert.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/config.h>
#include <minix/sched.h>
#include <minix/sysinfo.h>
#include <minix/type.h>
#include <machine/archtypes.h>
#include <lib.h>
#include "mproc.h"

#include <machine/archtypes.h>
#include <minix/timers.h>
#include "kernel/proc.h"

/*===========================================================================*
 *				sched_init				     *
 *===========================================================================*/
void sched_init(void)
{
	struct mproc *trmp;
	endpoint_t parent_e;
	int proc_nr, s;

	for (proc_nr=0, trmp=mproc; proc_nr < NR_PROCS; proc_nr++, trmp++) {
		/* Don't take over system processes. When the system starts,
		 * init is blocked on RTS_NO_QUANTUM until PM assigns a
		 * scheduler, from which other. Given that all other user
		 * processes are forked from init and system processes are
		 * managed by RS, there should be no other process that needs
		 * to be assigned a scheduler here */
		if (trmp->mp_flags & IN_USE && !(trmp->mp_flags & PRIV_PROC)) {
			/* Assert that it is indeed INIT_PROC_NR or its children */
			assert(_ENDPOINT_P(trmp->mp_endpoint) == INIT_PROC_NR || trmp->mp_parent == INIT_PROC_NR);

			/* For user processes, parent is INIT_PROC_NR */
			parent_e = mproc[INIT_PROC_NR].mp_endpoint;

			s = sched_start(SCHED_PROC_NR,	/* scheduler_e */
				trmp->mp_endpoint,	/* schedulee_e */
				parent_e,		/* parent_e */
				(unsigned)USER_Q, 		/* maxprio */
				USER_QUANTUM, 		/* quantum */
				-1,			/* don't change cpu (default) */
				&trmp->mp_scheduler);	/* *newsched_e */
			if (s != OK) {
				printf("PM: SCHED denied taking over scheduling of %s (endpoint %d): %d\n",
					trmp->mp_name, trmp->mp_endpoint, s);
			}
		}
 	}
}

/*===========================================================================*
 *				sched_start_user			     *
 *===========================================================================*/
int sched_start_user(endpoint_t scheduler_e, struct mproc *rmp)
{
	unsigned maxprio;
	endpoint_t inherit_from_e;
	int rv;

	/* Convert nice value to priority queue. */
	if ((rv = nice_to_priority(rmp->mp_nice, &maxprio)) != OK) {
		return rv;
	}

	/* Scheduler must know the parent.
	 * If parent is a privileged process, it is assumed RS manages it,
	 * so inherit from INIT_PROC_NR. Otherwise, inherit from the real parent.
	 */
	if (mproc[rmp->mp_parent].mp_flags & PRIV_PROC) {
		/* A privileged process's parent should ideally be RS or kernel, not a userland scheduler */
		assert(mproc[rmp->mp_parent].mp_scheduler == NONE || mproc[rmp->mp_parent].mp_scheduler == KERNEL);
		inherit_from_e = mproc[INIT_PROC_NR].mp_endpoint; /* Inherit from Init's scheduling parameters */
	} else {
		inherit_from_e = mproc[rmp->mp_parent].mp_endpoint;
	}

	/* Inherit quantum and schedule the process. */
	return sched_inherit(scheduler_e, 			/* scheduler_e */
		rmp->mp_endpoint, 			/* schedulee_e */
		inherit_from_e, 				/* parent_e */
		maxprio, 				/* maxprio */
		&rmp->mp_scheduler);			/* *newsched_e */
}

/*===========================================================================*
 *				sched_nice				     *
 *===========================================================================*/
int sched_nice(struct mproc *rmp, int nice_val)
{
	int rv;
	message m;
	unsigned maxprio;

	/* If the kernel is the scheduler, we don't allow messing with the
	 * priority directly via PM. If you want to control process priority,
	 * assign the process to a user-space scheduler. */
	if (rmp->mp_scheduler == KERNEL || rmp->mp_scheduler == NONE)
		return (EINVAL);

	if ((rv = nice_to_priority(nice_val, &maxprio)) != OK) {
		return rv;
	}

	memset(&m, 0, sizeof(m)); /* Initialize message */
	m.m_pm_sched_scheduling_set_nice.endpoint	= rmp->mp_endpoint;
	m.m_pm_sched_scheduling_set_nice.maxprio	= maxprio;
	if ((rv = _taskcall(rmp->mp_scheduler, SCHEDULING_SET_NICE, &m))) {
		return rv;
	}

	return (OK);
}