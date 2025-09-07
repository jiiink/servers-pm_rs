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

	/* Initialize scheduling for all user processes */
	for (proc_nr = 0, trmp = mproc; proc_nr < NR_PROCS; proc_nr++, trmp++) {
		/* Skip unused and system processes */
		if (!(trmp->mp_flags & IN_USE) || (trmp->mp_flags & PRIV_PROC)) {
			continue;
		}

		/* Only INIT should need scheduling setup at startup */
		assert(_ENDPOINT_P(trmp->mp_endpoint) == INIT_PROC_NR);

		parent_e = mproc[trmp->mp_parent].mp_endpoint;
		assert(parent_e == trmp->mp_endpoint);

		/* Start scheduling */
		s = sched_start(SCHED_PROC_NR, trmp->mp_endpoint, parent_e,
		               USER_Q, USER_QUANTUM, -1, &trmp->mp_scheduler);
		if (s != OK) {
			printf("PM: SCHED denied taking over scheduling of %s: %d\n",
			       trmp->mp_name, s);
		}
	}
}

/*===========================================================================*
 *				sched_start_user			     *
 *===========================================================================*/
int sched_start_user(endpoint_t ep, struct mproc *rmp)
{
	unsigned maxprio;
	endpoint_t inherit_from;
	int rv;

	if (rmp == NULL) {
		return EINVAL;
	}

	/* Convert nice to priority */
	rv = nice_to_priority(rmp->mp_nice, &maxprio);
	if (rv != OK) {
		return rv;
	}

	/* Determine inheritance source */
	if (mproc[rmp->mp_parent].mp_flags & PRIV_PROC) {
		assert(mproc[rmp->mp_parent].mp_scheduler == NONE);
		inherit_from = INIT_PROC_NR;
	} else {
		inherit_from = mproc[rmp->mp_parent].mp_endpoint;
	}

	/* Inherit scheduling settings */
	return sched_inherit(ep, rmp->mp_endpoint, inherit_from,
	                    maxprio, &rmp->mp_scheduler);
}

/*===========================================================================*
 *				sched_nice				     *
 *===========================================================================*/
int sched_nice(struct mproc *rmp, int nice)
{
	int rv;
	message m;
	unsigned maxprio;

	if (rmp == NULL) {
		return EINVAL;
	}

	/* Cannot adjust kernel-scheduled processes */
	if (rmp->mp_scheduler == KERNEL || rmp->mp_scheduler == NONE) {
		return EINVAL;
	}

	/* Convert nice to priority */
	rv = nice_to_priority(nice, &maxprio);
	if (rv != OK) {
		return rv;
	}

	/* Send request to scheduler */
	memset(&m, 0, sizeof(m));
	m.m_pm_sched_scheduling_set_nice.endpoint = rmp->mp_endpoint;
	m.m_pm_sched_scheduling_set_nice.maxprio = maxprio;

	rv = _taskcall(rmp->mp_scheduler, SCHEDULING_SET_NICE, &m);
	if (rv != OK) {
		return rv;
	}

	return OK;
}