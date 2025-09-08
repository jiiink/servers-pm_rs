#include "pm.h"
#include "mproc.h"
#include <assert.h>
#include <string.h>

#define NR_SUBS 4

static struct {
	endpoint_t endpt;
	unsigned int mask;
	unsigned int waiting;
} subs[NR_SUBS];

static unsigned int nsubs = 0;
static unsigned int nested = 0;

static unsigned int get_current_event(const struct mproc *rmp)
{
	if (rmp->mp_flags & EXITING) return PROC_EVENT_EXIT;
	if (rmp->mp_flags & UNPAUSED) return PROC_EVENT_SIGNAL;
	return 0;
}

static int find_sub_index_by_endpoint(endpoint_t endpt)
{
	unsigned int i;
	for (i = 0; i < nsubs; i++) {
		if (subs[i].endpt == endpt) return (int)i;
	}
	return -1;
}

static void resume_event(struct mproc *rmp)
{
	message m;
	unsigned int i, event;
	int r;

	assert(rmp->mp_flags & IN_USE);
	assert(rmp->mp_flags & EVENT_CALL);
	assert(rmp->mp_eventsub != NO_EVENTSUB);

	event = get_current_event(rmp);
	if (event == 0) panic("unknown event for flags %x", rmp->mp_flags);

	for (i = rmp->mp_eventsub; i < nsubs; i++, rmp->mp_eventsub++) {
		if (subs[i].mask & event) {
			memset(&m, 0, sizeof(m));
			m.m_type = PROC_EVENT;
			m.m_pm_lsys_proc_event.endpt = rmp->mp_endpoint;
			m.m_pm_lsys_proc_event.event = event;

			r = asynsend3(subs[i].endpt, &m, AMF_NOREPLY);
			if (r != OK) panic("asynsend failed: %d", r);

			assert(subs[i].waiting < NR_PROCS);
			subs[i].waiting++;

			return;
		}
	}

	rmp->mp_flags &= ~EVENT_CALL;
	rmp->mp_eventsub = NO_EVENTSUB;

	if (event == PROC_EVENT_EXIT)
		exit_restart(rmp);
	else if (event == PROC_EVENT_SIGNAL)
		restart_sigs(rmp);
}

static void remove_sub(unsigned int slot)
{
	struct mproc *rmp;

	if (slot >= nsubs) return;

	if (slot < nsubs - 1) {
		memmove(&subs[slot], &subs[slot + 1],
		    (nsubs - slot - 1) * sizeof(subs[0]));
	}
	nsubs--;
	memset(&subs[nsubs], 0, sizeof(subs[0]));

	for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
		if ((rmp->mp_flags & (IN_USE | EVENT_CALL)) != (IN_USE | EVENT_CALL))
			continue;

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

int do_proceventmask(void)
{
	unsigned int i, mask;

	if (!(mp->mp_flags & PRIV_PROC))
		return EPERM;

	mask = m_in.m_lsys_pm_proceventmask.mask;

	for (i = 0; i < nsubs; i++) {
		if (subs[i].endpt == who_e) {
			if (mask == 0 && subs[i].waiting == 0)
				remove_sub(i);
			else
				subs[i].mask = mask;
			return OK;
		}
	}

	if (mask == 0)
		return OK;

	if (nsubs == __arraycount(subs)) {
		printf("PM: too many process event subscribers!\n");
		return ENOMEM;
	}

	subs[nsubs].endpt = who_e;
	subs[nsubs].mask = mask;
	subs[nsubs].waiting = 0;
	nsubs++;

	return OK;
}

int do_proc_event_reply(void)
{
	struct mproc *rmp;
	endpoint_t endpt;
	unsigned int i, event;
	int slot;

	assert(nested == 0);

	if (!(mp->mp_flags & PRIV_PROC))
		return ENOSYS;

	endpt = m_in.m_pm_lsys_proc_event.endpt;
	if (pm_isokendpt(endpt, &slot) != OK) {
		printf("PM: proc event reply from %d for invalid endpt %d\n",
		    who_e, endpt);
		return SUSPEND;
	}

	rmp = &mproc[slot];

	if (!(rmp->mp_flags & EVENT_CALL)) {
		printf("PM: proc event reply from %d for endpt %d, no event\n",
		    who_e, endpt);
		return SUSPEND;
	}

	if (rmp->mp_eventsub == NO_EVENTSUB || (unsigned int)rmp->mp_eventsub >= nsubs) {
		printf("PM: proc event reply from %d for endpt %d index %d\n",
		    who_e, endpt, rmp->mp_eventsub);
		return SUSPEND;
	}

	i = (unsigned int)rmp->mp_eventsub;

	if (subs[i].endpt != who_e) {
		printf("PM: proc event reply for %d from %d instead of %d\n",
		    endpt, who_e, subs[i].endpt);
		return SUSPEND;
	}

	event = get_current_event(rmp);
	if (event == 0) {
		printf("PM: proc event reply from %d for %d, bad flags %x\n",
		    who_e, endpt, rmp->mp_flags);
		return SUSPEND;
	}

	if (m_in.m_pm_lsys_proc_event.event != event) {
		printf("PM: proc event reply from %d for %d for event %d instead of %d\n",
		    who_e, endpt, m_in.m_pm_lsys_proc_event.event, event);
		return SUSPEND;
	}

	assert(subs[i].waiting > 0);
	subs[i].waiting--;

	if (subs[i].mask == 0 && subs[i].waiting == 0) {
		remove_sub(i);
	} else {
		rmp->mp_eventsub++;
		resume_event(rmp);
	}

	return SUSPEND;
}

void publish_event(struct mproc *rmp)
{
	int idx;

	assert(nested == 0);
	assert((rmp->mp_flags & (IN_USE | EVENT_CALL)) == IN_USE);
	assert(rmp->mp_eventsub == NO_EVENTSUB);

	if ((rmp->mp_flags & (PRIV_PROC | EXITING)) == (PRIV_PROC | EXITING)) {
		idx = find_sub_index_by_endpoint(rmp->mp_endpoint);
		if (idx >= 0) remove_sub((unsigned int)idx);
	}

	rmp->mp_flags |= EVENT_CALL;
	rmp->mp_eventsub = 0;

	resume_event(rmp);
}