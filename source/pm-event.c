#include "pm.h"
#include "mproc.h"
#include <assert.h>

#define NR_SUBS 4

typedef struct {
    endpoint_t endpt;
    unsigned int mask;
    unsigned int waiting;
} Sub;

static Sub subs[NR_SUBS];
static unsigned int nsubs = 0;
static unsigned int nested = 0;

static void publish_event_to_next_subscriber(struct mproc *rmp, unsigned int event) {
    message m;
    int r;

    for (unsigned int i = rmp->mp_eventsub; i < nsubs; i++) {
        if (subs[i].mask & event) {
            rmp->mp_eventsub = i;
            memset(&m, 0, sizeof(m));
            m.m_type = PROC_EVENT;
            m.m_pm_lsys_proc_event.endpt = rmp->mp_endpoint;
            m.m_pm_lsys_proc_event.event = event;
            r = asynsend3(subs[i].endpt, &m, AMF_NOREPLY);
            if (r != OK) panic("asynsend failed: %d", r);
            subs[i].waiting++;
            return;
        }
    }

    rmp->mp_flags &= ~EVENT_CALL;
    rmp->mp_eventsub = NO_EVENTSUB;
    if (event == PROC_EVENT_EXIT) exit_restart(rmp);
    else if (event == PROC_EVENT_SIGNAL) restart_sigs(rmp);
}

static void resume_event(struct mproc *rmp) {
    unsigned int event = (rmp->mp_flags & EXITING) ? PROC_EVENT_EXIT : PROC_EVENT_SIGNAL;
    publish_event_to_next_subscriber(rmp, event);
}

static void remove_sub(unsigned int index) {
    for (unsigned int i = index; i < nsubs - 1; i++) subs[i] = subs[i + 1];
    nsubs--;

    for (struct mproc *rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
        if ((rmp->mp_flags & (IN_USE | EVENT_CALL)) != (IN_USE | EVENT_CALL)) continue;

        if (rmp->mp_eventsub == index) {
            nested++;
            resume_event(rmp);
            nested--;
        } else if (rmp->mp_eventsub > index) {
            rmp->mp_eventsub--;
        }
    }
}

int do_proceventmask(void) {
    unsigned int mask = m_in.m_lsys_pm_proceventmask.mask;

    if (!(mp->mp_flags & PRIV_PROC)) return EPERM;

    for (unsigned int i = 0; i < nsubs; i++) {
        if (subs[i].endpt == who_e) {
            if (mask == 0 && subs[i].waiting == 0) remove_sub(i);
            else subs[i].mask = mask;
            return OK;
        }
    }

    if (mask == 0) return OK;
    if (nsubs >= NR_SUBS) return ENOMEM;

    subs[nsubs++] = (Sub){who_e, mask, 0};
    return OK;
}

int do_proc_event_reply(void) {
    int slot;
    endpoint_t endpt = m_in.m_pm_lsys_proc_event.endpt;
    unsigned int event = (mp->mp_flags & EXITING) ? PROC_EVENT_EXIT : PROC_EVENT_SIGNAL;

    if (!(mp->mp_flags & PRIV_PROC)) return ENOSYS;
    if (pm_isokendpt(endpt, &slot) != OK) return SUSPEND;

    struct mproc *rmp = &mproc[slot];
    unsigned int i = rmp->mp_eventsub;

    if (!(rmp->mp_flags & EVENT_CALL) || i >= nsubs || subs[i].endpt != who_e || m_in.m_pm_lsys_proc_event.event != event) {
        return SUSPEND;
    }

    subs[i].waiting--;
    if (subs[i].mask == 0 && subs[i].waiting == 0) remove_sub(i);
    else {
        rmp->mp_eventsub++;
        resume_event(rmp);
    }

    return SUSPEND;
}

void publish_event(struct mproc *rmp) {
    if ((rmp->mp_flags & (PRIV_PROC | EXITING)) == (PRIV_PROC | EXITING)) {
        for (unsigned int i = 0; i < nsubs; i++) {
            if (subs[i].endpt == rmp->mp_endpoint) {
                remove_sub(i);
                break;
            }
        }
    }

    rmp->mp_flags |= EVENT_CALL;
    rmp->mp_eventsub = 0;
    resume_event(rmp);
}