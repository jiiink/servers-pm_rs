/*
 * This file implements a generic process event publish/subscribe facility.
 */

#include "pm.h"
#include "mproc.h"
#include <assert.h>

#define NR_SUBS 4

static struct subscriber {
	endpoint_t endpt;
	unsigned int mask;
	unsigned int waiting;
} subs[NR_SUBS];

static unsigned int nsubs = 0;
static unsigned int nested = 0;

/* Function prototypes */
static void resume_event(struct mproc *rmp);
static void remove_sub(unsigned int slot);
static int validate_subscriber(endpoint_t endpt);
static int find_subscriber(endpoint_t endpt);

/*===========================================================================*
 *				validate_subscriber			     *
 *===========================================================================*/
static int validate_subscriber(endpoint_t endpt)
{
	/* Validate that this is a system service */
	if (!(mp->mp_flags & PRIV_PROC)) {
		return EPERM;
	}
	return OK;
}

/*===========================================================================*
 *				find_subscriber				     *
 *===========================================================================*/
static int find_subscriber(endpoint_t endpt)
{
	unsigned int i;
	
	for (i = 0; i < nsubs; i++) {
		if (subs[i].endpt == endpt) {
			return (int)i;
		}
	}
	return -1;
}

/*===========================================================================*
 *				resume_event				     *
 *===========================================================================*/
static void resume_event(struct mproc *rmp)
{
	message m;
	unsigned int i, event;
	int r;

	if (rmp == NULL) {
		return;
	}

	assert(rmp->mp_flags & IN_USE);
	assert(rmp->mp_flags & EVENT_CALL);
	assert(rmp->mp_eventsub != NO_EVENTSUB);

	/* Determine event type */
	if (rmp->mp_flags & EXITING) {
		event = PROC_EVENT_EXIT;
	} else if (rmp->mp_flags & UNPAUSED) {
		event = PROC_EVENT_SIGNAL;
	} else {
		panic("unknown event for flags %x", rmp->mp_flags);
	}

	/* Send to next interested subscriber */
	for (i = rmp->mp_eventsub; i < nsubs; i++, rmp->mp_eventsub++) {
		if (subs[i].mask & event) {
			memset(&m, 0, sizeof(m));
			m.m_type = PROC_EVENT;
			m.m_pm_lsys_proc_event.endpt = rmp->mp_endpoint;
			m.m_pm_lsys_proc_event.event = event;

			r = asynsend3(subs[i].endpt, &m, AMF_NOREPLY);
			if (r != OK) {
				panic("asynsend failed: %d", r);
			}

			assert(subs[i].waiting < NR_PROCS);
			subs[i].waiting++;
			return;
		}
	}

	/* No more subscribers, resume event */
	rmp->mp_flags &= ~EVENT_CALL;
	rmp->mp_eventsub = NO_EVENTSUB;

	if (event == PROC_EVENT_EXIT) {
		exit_restart(rmp);
	} else if (event == PROC_EVENT_SIGNAL) {
		restart_sigs(rmp);
	}
}

/*===========================================================================*
 *				remove_sub				     *
 *===========================================================================*/
static void remove_sub(unsigned int slot)
{
	struct mproc *rmp;
	unsigned int i;

	if (slot >= nsubs) {
		return;
	}

	/* Shift remaining subscribers */
	for (i = slot; i < nsubs - 1; i++) {
		subs[i] = subs[i + 1];
	}
	nsubs--;

	/* Update affected processes */
	for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
		if ((rmp->mp_flags & (IN_USE | EVENT_CALL)) != 
		    (IN_USE | EVENT_CALL)) {
			continue;
		}

		assert(rmp->mp_eventsub != NO_EVENTSUB);

		if ((unsigned int)rmp->mp_eventsub == slot) {
			nested++;
			resume_event(rmp);
			nested--;
		} else if ((unsigned int)rmp->mp_eventsub > slot) {
			rmp->mp_eventsub--;
		}
	}
}

/*===========================================================================*
 *				do_proceventmask			     *
 *===========================================================================*/
int do_proceventmask(void)
{
	unsigned int mask;
	int slot;
	int r;

	/* Validate permissions */
	r = validate_subscriber(who_e);
	if (r != OK) {
		return r;
	}

	mask = m_in.m_lsys_pm_proceventmask.mask;

	/* Check for existing subscription */
	slot = find_subscriber(who_e);
	if (slot >= 0) {
		if (mask == 0 && subs[slot].waiting == 0) {
			remove_sub((unsigned int)slot);
		} else {
			subs[slot].mask = mask;
		}
		return OK;
	}

	/* Add new subscription if mask is non-zero */
	if (mask == 0) {
		return OK;
	}

	/* Check for available slot */
	if (nsubs >= NR_SUBS) {
		printf("PM: too many process event subscribers!\n");
		return ENOMEM;
	}

	/* Add new subscriber */
	subs[nsubs].endpt = who_e;
	subs[nsubs].mask = mask;
	subs[nsubs].waiting = 0;
	nsubs++;

	return OK;
}

/*===========================================================================*
 *				do_proc_event_reply			     *
 *===========================================================================*/
int do_proc_event_reply(void)
{
	struct mproc *rmp;
	endpoint_t endpt;
	unsigned int i, event;
	int slot;

	assert(nested == 0);

	/* Validate permissions */
	if (!(mp->mp_flags & PRIV_PROC)) {
		return ENOSYS;
	}

	/* Validate endpoint */
	endpt = m_in.m_pm_lsys_proc_event.endpt;
	if (pm_isokendpt(endpt, &slot) != OK) {
		printf("PM: proc event reply from %d for invalid endpt %d\n",
		       who_e, endpt);
		return SUSPEND;
	}

	rmp = &mproc[slot];

	/* Validate state */
	if (!(rmp->mp_flags & EVENT_CALL)) {
		printf("PM: proc event reply from %d for endpt %d, no event\n",
		       who_e, endpt);
		return SUSPEND;
	}

	if (rmp->mp_eventsub == NO_EVENTSUB ||
	    (unsigned int)rmp->mp_eventsub >= nsubs) {
		printf("PM: proc event reply from %d for endpt %d index %d\n",
		       who_e, endpt, rmp->mp_eventsub);
		return SUSPEND;
	}

	i = rmp->mp_eventsub;
	if (subs[i].endpt != who_e) {
		printf("PM: proc event reply for %d from %d instead of %d\n",
		       endpt, who_e, subs[i].endpt);
		return SUSPEND;
	}

	/* Determine event type */
	if (rmp->mp_flags & EXITING) {
		event = PROC_EVENT_EXIT;
	} else if (rmp->mp_flags & UNPAUSED) {
		event = PROC_EVENT_SIGNAL;
	} else {
		printf("PM: proc event reply from %d for %d, bad flags %x\n",
		       who_e, endpt, rmp->mp_flags);
		return SUSPEND;
	}

	if (m_in.m_pm_lsys_proc_event.event != event) {
		printf("PM: proc event reply from %d for %d for event %d "
		       "instead of %d\n", who_e, endpt,
		       m_in.m_pm_lsys_proc_event.event, event);
		return SUSPEND;
	}

	assert(subs[i].waiting > 0);
	subs[i].waiting--;

	/* Clean up or continue */
	if (subs[i].mask == 0 && subs[i].waiting == 0) {
		remove_sub(i);
	} else {
		rmp->mp_eventsub++;
		resume_event(rmp);
	}

	return SUSPEND;
}

/*===========================================================================*
 *				publish_event				     *
 *===========================================================================*/
void publish_event(struct mproc *rmp)
{
	unsigned int i;

	if (rmp == NULL) {
		return;
	}

	assert(nested == 0);
	assert((rmp->mp_flags & (IN_USE | EVENT_CALL)) == IN_USE);
	assert(rmp->mp_eventsub == NO_EVENTSUB);

	/* Check if exiting service was a subscriber */
	if ((rmp->mp_flags & (PRIV_PROC | EXITING)) == (PRIV_PROC | EXITING)) {
		for (i = 0; i < nsubs; i++) {
			if (subs[i].endpt == rmp->mp_endpoint) {
				remove_sub(i);
				break;
			}
		}
	}

	/* Start event processing */
	rmp->mp_flags |= EVENT_CALL;
	rmp->mp_eventsub = 0;
	resume_event(rmp);
}