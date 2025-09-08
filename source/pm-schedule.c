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

void sched_init(void)
{
    struct mproc *trmp;
    endpoint_t parent_e;
    int proc_nr, s;

    for (proc_nr = 0, trmp = mproc; proc_nr < NR_PROCS; proc_nr++, trmp++) {
        if (trmp->mp_flags & IN_USE && !(trmp->mp_flags & PRIV_PROC)) {
            assert(_ENDPOINT_P(trmp->mp_endpoint) == INIT_PROC_NR);
            parent_e = mproc[trmp->mp_parent].mp_endpoint;
            assert(parent_e == trmp->mp_endpoint);
            s = sched_start(SCHED_PROC_NR, trmp->mp_endpoint, parent_e, USER_Q, 
                            USER_QUANTUM, -1, &trmp->mp_scheduler);
            if (s != OK) {
                printf("PM: SCHED denied taking over scheduling of %s: %d\n",
                       trmp->mp_name, s);
            }
        }
    }
}

int sched_start_user(endpoint_t ep, struct mproc *rmp)
{
    unsigned maxprio;
    endpoint_t inherit_from;
    int rv;

    if ((rv = nice_to_priority(rmp->mp_nice, &maxprio)) != OK) {
        return rv;
    }

    inherit_from = (mproc[rmp->mp_parent].mp_flags & PRIV_PROC) ? INIT_PROC_NR 
                   : mproc[rmp->mp_parent].mp_endpoint;

    return sched_inherit(ep, rmp->mp_endpoint, inherit_from, maxprio, &rmp->mp_scheduler);
}

int sched_nice(struct mproc *rmp, int nice)
{
    int rv;
    message m;
    unsigned maxprio;

    if (rmp->mp_scheduler == KERNEL || rmp->mp_scheduler == NONE) {
        return (EINVAL);
    }

    if ((rv = nice_to_priority(nice, &maxprio)) != OK) {
        return rv;
    }

    m.m_pm_sched_scheduling_set_nice.endpoint = rmp->mp_endpoint;
    m.m_pm_sched_scheduling_set_nice.maxprio = maxprio;
    return _taskcall(rmp->mp_scheduler, SCHEDULING_SET_NICE, &m) == OK ? OK : rv;
}