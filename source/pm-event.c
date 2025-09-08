/*
 * This file implements a generic process event publish/subscribe facility.
 * The facility for use by non-core system services that implement part of the
 * userland system call interface.  Currently, it supports two events: a
 * process catching a signal, and a process being terminated.  A subscribing
 * service would typically use such events to interrupt a blocking system call
 * and/or clean up process-bound resources.  As of writing, the only service
 * that uses this facility is the System V IPC server.
 *
 * Each of these events will be published to subscribing services right after
 * VFS has acknowledged that it has processed the same event.  For each
 * subscriber, in turn, the process will be blocked (with the EVENT_CALL flag
 * set) until the subscriber acknowledges the event or PM learns that the
 * subscriber has died.  Thus, each subscriber adds a serialized messaging
 * roundtrip for each subscribed event.
 *
 * The one and only reason for this synchronous, serialized approach is that it
 * avoids PM queuing up too many asynchronous messages.  In theory, each
 * running process may have an event pending, and thus, the serial synchronous
 * approach requires NR_PROCS asynsend slots.  For a parallel synchronous
 * approach, this would increase to (NR_PROCS*NR_SUBS).  Worse yet, for an
 * asynchronous event notification approach, the number of messages that PM can
 * end up queuing is potentially unbounded, so that is certainly not an option.
 * At this moment, we expect only one subscriber (the IPC server) which makes
 * the serial vs parallel point less relevant.
 *
 * It is not possible to subscribe to events from certain processes only.  If
 * a service were to subscribe to process events as part of a system call by
 * a process (e.g., semop(2) in the case of the IPC server), it may subscribe
 * "too late" and already have missed a signal event for the process calling
 * semop(2), for example.  Resolving such race conditions would require major
 * infrastructure changes.
 *
 * A server may however change its event subscription mask at runtime, so as to
 * limit the number of event messages it receives in a crude fashion.  For the
 * same race-condition reasons, new subscriptions must always be made when
 * processing a message that is *not* a system call potentially affected by
 * events.  In the case of the IPC server, it may subscribe to events from
 * semget(2) but not semop(2).  For signal events, the delay call system
 * guarantees the safety of this approach; for exit events, the message type
 * prioritization does (which is not great; see the TODO item in forkexit.c).
 *
 * After changing its mask, a subscribing service may still receive messages
 * for events it is no longer subscribed to.  It should acknowledge these
 * messages by sending a reply as usual.
 */

#include "pm.h"
#include "mproc.h"
#include <assert.h>

/*
 * A realistic upper bound for the number of subscribing services.  The process
 * event notification system adds a round trip to a service for each subscriber
 * and uses asynchronous messaging to boot, so clearly it does not scale to
 * numbers larger than this.
 */
#define PM_MAX_EVENT_SUBS	4 /* Changed NR_SUBS to PM_MAX_EVENT_SUBS for clarity and to avoid conflict */

typedef struct {
	endpoint_t endpt;		/* endpoint of subscriber */
	unsigned int mask;		/* interests bit mask (PROC_EVENT_) */
	unsigned int waiting;		/* # procs blocked on reply from it */
} PmEventSubscriber;

static PmEventSubscriber event_subscribers[PM_MAX_EVENT_SUBS];
static unsigned int num_event_subscribers = 0;
static unsigned int nested_event_calls = 0; /* Renamed 'nested' for clarity */

static void resume_event(struct mproc * rmp);
static void remove_subscriber(unsigned int slot);

/*===========================================================================*
 *				resume_event				     *
 *===========================================================================*/
static void
resume_event(struct mproc * rmp)
{
	message m;
	unsigned int i, event_type;
	int r;

	assert((rmp->mp_flags & IN_USE) && (rmp->mp_flags & EVENT_CALL));
	assert(rmp->mp_eventsub != NO_EVENTSUB);

	/* Determine which event is being processed. */
	if (rmp->mp_flags & EXITING)
		event_type = PROC_EVENT_EXIT;
	else if (rmp->mp_flags & UNPAUSED)
		event_type = PROC_EVENT_SIGNAL;
	else
		panic("unknown event for flags %x", rmp->mp_flags);

	/* Iterate through subscribers to find the next one interested in this event. */
	for (i = (unsigned int)rmp->mp_eventsub; i < num_event_subscribers; i++, rmp->mp_eventsub++) {
		if (event_subscribers[i].mask & event_type) {
			memset(&m, 0, sizeof(m));
			m.m_type = PROC_EVENT;
			m.m_pm_lsys_proc_event.endpt = rmp->mp_endpoint;
			m.m_pm_lsys_proc_event.event = event_type;

			/* Send an asynchronous notification. AMF_NOREPLY indicates
			 * that the sender does not expect an immediate IPC reply,
			 * but PM will wait for PROC_EVENT_REPLY to clear EVENT_CALL.
			 */
			r = asynsend3(event_subscribers[i].endpt, &m, AMF_NOREPLY);
			if (r != OK) {
				/* This is a serious error; a critical system service
				 * could not be notified. Panic to avoid inconsistent state.
				 */
				panic("asynsend failed: %d", r);
			}

			assert(event_subscribers[i].waiting < NR_PROCS);
			event_subscribers[i].waiting++;

			return; /* Event notification sent, process remains blocked. */
		}
	}

	/* No more subscribers to be notified, resume the actual event handling. */
	rmp->mp_flags &= ~EVENT_CALL;
	rmp->mp_eventsub = NO_EVENTSUB;

	if (event_type == PROC_EVENT_EXIT)
		exit_restart(rmp);
	else if (event_type == PROC_EVENT_SIGNAL)
		restart_sigs(rmp);
}

/*===========================================================================*
 *				remove_subscriber			     *
 *===========================================================================*/
static void
remove_subscriber(unsigned int slot)
{
	struct mproc *rmp;
	unsigned int i;

	/* The loop below needs the remaining items to be kept in order. */
	for (i = slot; i < num_event_subscribers - 1; i++)
		event_subscribers[i] = event_subscribers[i + 1];
	num_event_subscribers--;

	/* Adjust affected processes' event subscriber indexes to match. */
	for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
		if ((rmp->mp_flags & (IN_USE | EVENT_CALL)) !=
		    (IN_USE | EVENT_CALL))
			continue;
		assert(rmp->mp_eventsub != NO_EVENTSUB);

		/*
		 * If this process was waiting for the removed subscriber,
		 * resume its event handling. Otherwise, just decrement the index.
		 */
		if ((unsigned int)rmp->mp_eventsub == slot) {
			nested_event_calls++;
			resume_event(rmp);
			nested_event_calls--;
		} else if ((unsigned int)rmp->mp_eventsub > slot)
			rmp->mp_eventsub--;
	}
}

/*===========================================================================*
 *				do_proceventmask			     *
 *===========================================================================*/
int
do_proceventmask(void)
{
	unsigned int i, mask;

	/* This call is for privileged system services only. */
	if (!(mp->mp_flags & PRIV_PROC))
		return EPERM;

	mask = (unsigned int)m_in.m_lsys_pm_proceventmask.mask;

	/*
	 * First check if we need to update or remove an existing entry.
	 */
	for (i = 0; i < num_event_subscribers; i++) {
		if (event_subscribers[i].endpt == who_e) {
			if (mask == 0 && event_subscribers[i].waiting == 0) {
				/* No longer interested and no pending events, remove. */
				remove_subscriber(i);
            } else {
				/* Update mask, even if waiting (to reflect new interest). */
				event_subscribers[i].mask = mask;
            }
			return OK;
		}
	}

	/* Add a new entry, unless the given mask is empty. */
	if (mask == 0)
		return OK; /* No mask, no subscription, no error. */

	/* Check for available slots. */
	if (num_event_subscribers == __arraycount(event_subscribers)) {
		printf("PM: too many process event subscribers!\n");
		return ENOMEM;
	}

	event_subscribers[num_event_subscribers].endpt = who_e;
	event_subscribers[num_event_subscribers].mask = mask;
	event_subscribers[num_event_subscribers].waiting = 0; /* New subscriber is not waiting */
	num_event_subscribers++;

	return OK;
}

/*===========================================================================*
 *				do_proc_event_reply			     *
 *===========================================================================*/
int
do_proc_event_reply(void)
{
	struct mproc *rmp;
	endpoint_t event_proc_endpoint;
	unsigned int i, event_type;
	int slot_nr;

	assert(nested_event_calls == 0);

	/*
	 * Is this an accidental call from a misguided user process?
	 * Politely tell it to go away.
	 */
	if (!(mp->mp_flags & PRIV_PROC))
		return ENOSYS;

	/* Validate the endpoint for which the reply is intended. */
	event_proc_endpoint = m_in.m_pm_lsys_proc_event.endpt;
	if (pm_isokendpt(event_proc_endpoint, &slot_nr) != OK) {
		printf("PM: proc event reply from %d for invalid endpt %d\n",
		    who_e, event_proc_endpoint);
		return SUSPEND;
	}
	rmp = &mproc[slot_nr];

	/* Check if the process is indeed blocked on an event. */
	if (!(rmp->mp_flags & EVENT_CALL)) {
		printf("PM: proc event reply from %d for endpt %d, no event pending\n",
		    who_e, event_proc_endpoint);
		return SUSPEND;
	}

	/* Check if the subscriber index is valid. */
	if (rmp->mp_eventsub == NO_EVENTSUB ||
	    (unsigned int)rmp->mp_eventsub >= num_event_subscribers) {
		printf("PM: proc event reply from %d for endpt %d with invalid subscriber index %d\n",
		    who_e, event_proc_endpoint, rmp->mp_eventsub);
		return SUSPEND;
	}
	i = (unsigned int)rmp->mp_eventsub;

	/* Verify the reply came from the expected subscriber. */
	if (event_subscribers[i].endpt != who_e) {
		printf("PM: proc event reply for %d from %d instead of expected %d\n",
		    event_proc_endpoint, who_e, event_subscribers[i].endpt);
		return SUSPEND;
	}

	/* Determine the expected event type for consistency check. */
	if (rmp->mp_flags & EXITING)
		event_type = PROC_EVENT_EXIT;
	else if (rmp->mp_flags & UNPAUSED)
		event_type = PROC_EVENT_SIGNAL;
	else {
		printf("PM: proc event reply from %d for %d, bad flags %x\n",
		    who_e, event_proc_endpoint, rmp->mp_flags);
		return SUSPEND;
	}

	/* Check if the reported event type matches the actual event. */
	if (m_in.m_pm_lsys_proc_event.event != event_type) {
		printf("PM: proc event reply from %d for %d for event %d "
		    "instead of expected %d\n", who_e, event_proc_endpoint,
		    m_in.m_pm_lsys_proc_event.event, event_type);
		return SUSPEND;
	}

	/*
	 * Do NOT check the event against the subscriber's event mask, since a
	 * service may have unsubscribed from an event while it has yet to
	 * process some leftover notifications for that event.  We could decide
	 * not to wait for the replies to those leftover notifications upon
	 * unsubscription, but that could result in problems upon quick
	 * resubscription, and such cases may in fact happen in practice.
	 */

	assert(event_subscribers[i].waiting > 0);
	event_subscribers[i].waiting--;

	/*
	 * If we are now no longer waiting for any replies from an already
	 * unsubscribed (but alive) service, remove it from the set now; this
	 * will also resume events for the current process.  In the normal case
	 * however, let the current process move on to the next subscriber if
	 * there are more, and the actual event otherwise.
	 */
	if (event_subscribers[i].mask == 0 && event_subscribers[i].waiting == 0) {
		remove_subscriber(i);
	} else {
		rmp->mp_eventsub++; /* Move to the next potential subscriber */
		resume_event(rmp);  /* Continue with event processing for rmp */
	}

	/* In any case, do not reply to this reply message. */
	return SUSPEND;
}

/*===========================================================================*
 *				publish_event				     *
 *===========================================================================*/
void
publish_event(struct mproc * rmp)
{
	unsigned int i;

	assert(nested_event_calls == 0);
	assert((rmp->mp_flags & (IN_USE | EVENT_CALL)) == IN_USE);
	assert(rmp->mp_eventsub == NO_EVENTSUB);

	/*
	 * If a system service exited, we have to check if it was subscribed to
	 * process events.  If so, we have to remove it from the set and resume
	 * any processes blocked on an event call to that service.
	 */
	if ((rmp->mp_flags & (PRIV_PROC | EXITING)) == (PRIV_PROC | EXITING)) {
		for (i = 0; i < num_event_subscribers; i++) {
			if (event_subscribers[i].endpt == rmp->mp_endpoint) {
				/*
				 * If the wait count is nonzero, we may or may
				 * not get additional replies from this service
				 * later.  Those will be ignored.
				 */
				remove_subscriber(i);
				break;
			}
		}
	}

	/*
	 * Either send an event message to the first subscriber, or if there
	 * are no subscribers, resume processing the event right away.
	 */
	rmp->mp_flags |= EVENT_CALL;
	rmp->mp_eventsub = 0; /* Start checking from the first subscriber. */

	resume_event(rmp);
}