#include "pm.h"
#include <minix/callnr.h>
#include <minix/com.h>
#include <signal.h>
#include <sys/time.h>
#include "mproc.h"

int do_gettime(void) {
    clock_t ticks, realtime, clock;
    time_t boottime;
    int s;

    if ((s = getuptime(&ticks, &realtime, &boottime)) != OK)
        return s;

    switch (m_in.m_lc_pm_time.clk_id) {
        case CLOCK_REALTIME:
            clock = realtime;
            break;
        case CLOCK_MONOTONIC:
            clock = ticks;
            break;
        default:
            return EINVAL;
    }

    mp->mp_reply.m_pm_lc_time.sec = boottime + (clock / system_hz);
    mp->mp_reply.m_pm_lc_time.nsec = (uint32_t)((clock % system_hz) * 1000000000ULL / system_hz);

    return OK;
}

int do_getres(void) {
    if (m_in.m_lc_pm_time.clk_id != CLOCK_REALTIME && m_in.m_lc_pm_time.clk_id != CLOCK_MONOTONIC)
        return EINVAL;

    mp->mp_reply.m_pm_lc_time.sec = 0;
    mp->mp_reply.m_pm_lc_time.nsec = 1000000000 / system_hz;
    return OK;
}

int do_settime(void) {
    if (mp->mp_effuid != SUPER_USER)
        return EPERM;

    if (m_in.m_lc_pm_time.clk_id != CLOCK_REALTIME)
        return EINVAL;

    return sys_settime(m_in.m_lc_pm_time.now, m_in.m_lc_pm_time.clk_id,
                       m_in.m_lc_pm_time.sec, m_in.m_lc_pm_time.nsec);
}

int do_time(void) {
    struct timespec tv;
    clock_time(&tv);

    mp->mp_reply.m_pm_lc_time.sec = tv.tv_sec;
    mp->mp_reply.m_pm_lc_time.nsec = tv.tv_nsec;
    return OK;
}

int do_stime(void) {
    clock_t uptime, realtime;
    time_t boottime;
    int s;

    if (mp->mp_effuid != SUPER_USER)
        return EPERM;

    if ((s = getuptime(&uptime, &realtime, &boottime)) != OK)
        return s;

    boottime = m_in.m_lc_pm_time.sec - (realtime / system_hz);
    s = sys_stime(boottime);
    if (s != OK)
        return s;

    return OK;
}