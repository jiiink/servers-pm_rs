#include "pm.h"
#include <assert.h>
#include <lib.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/config.h>
#include <minix/sched.h>
#include <minix/type.h>
#include <machine/archtypes.h>
#include "mproc.h"

void sched_init(void)
{
	struct mproc *rmp;
	endpoint_t parent_e;
	int proc_nr, s;

	for (proc_nr = 0, rmp = mproc; proc_nr < NR_PROCS; proc_nr++, rmp++) {
		if (!(rmp->mp_flags & IN_USE) || (rmp->mp_flags & PRIV_PROC)) {
			continue;
		}

		assert(_ENDPOINT_P(rmp->mp_endpoint) == INIT_PROC_NR);
		parent_e = mproc[rmp->mp_parent].mp_endpoint;
		assert(parent_e == rmp->mp_endpoint);

		s = sched_start(
			SCHED_PROC_NR,
			rmp->mp_endpoint,
			parent_e,
			USER_Q,
			USER_QUANTUM,
			-1,
			&rmp->mp_scheduler
		);
		if (s != OK) {
			printf("PM: SCHED denied taking over scheduling of %s: %d\n",
				rmp->mp_name, s);
		}
	}
}

int sched_start_user(endpoint_t ep, struct mproc *rmp)
{
	unsigned maxprio;
	endpoint_t inherit_from;
	int rv;

	rv = nice_to_priority(rmp->mp_nice, &maxprio);
	if (rv != OK) {
		return rv;
	}

	if (mproc[rmp->mp_parent].mp_flags & PRIV_PROC) {
		assert(mproc[rmp->mp_parent].mp_scheduler == NONE);
		inherit_from = INIT_PROC_NR;
	} else {
		inherit_from = mproc[rmp->mp_parent].mp_endpoint;
	}

	return sched_inherit(
		ep,
		rmp->mp_endpoint,
		inherit_from,
		maxprio,
		&rmp->mp_scheduler
	);
}

int sched_nice(struct mproc *rmp, int nice)
{
	int rv;
	message m;
	unsigned maxprio;

	if (rmp->mp_scheduler == KERNEL || rmp->mp_scheduler == NONE) {
		return EINVAL;
	}

	rv = nice_to_priority(nice, &maxprio);
	if (rv != OK) {
		return rv;
	}

	m.m_pm_sched_scheduling_set_nice.endpoint = rmp->mp_endpoint;
	m.m_pm_sched_scheduling_set_nice.maxprio = maxprio;

	rv = _taskcall(rmp->mp_scheduler, SCHEDULING_SET_NICE, &m);
	if (rv != OK) {
		return rv;
	}

	return OK;
}