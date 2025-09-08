/* This file takes care of those system calls that deal with time.
 *
 * The entry points into this file are
 *   do_getres:		perform the CLOCK_GETRES system call
 *   do_gettime:	perform the CLOCK_GETTIME system call
 *   do_settime:	perform the CLOCK_SETTIME system call
 *   do_time:		perform the GETTIMEOFDAY system call
 *   do_stime:		perform the STIME system call
 */

#include "pm.h"
#include <minix/callnr.h>
#include <minix/com.h>
#include <signal.h>
#include <sys/time.h>
#include "mproc.h"

/*===========================================================================*
 *				do_gettime				     *
 *===========================================================================*/
int
do_gettime(void)
{
  clock_t ticks_uptime, realtime, clock_val;
  time_t boottime_sec;
  int s;

  if ( (s=getuptime(&ticks_uptime, &realtime, &boottime_sec)) != OK)
  	panic("do_gettime couldn't get uptime: %d", s);

  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
		clock_val = realtime; /* Realtime in ticks since boot */
		break;
	case CLOCK_MONOTONIC:
		clock_val = ticks_uptime; /* Uptime in ticks */
		break;
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }

  /* Convert ticks to seconds and nanoseconds. */
  mp->mp_reply.m_pm_lc_time.sec = boottime_sec + (clock_val / system_hz);
  mp->mp_reply.m_pm_lc_time.nsec =
	(uint32_t) ((clock_val % system_hz) * 1000000000ULL / system_hz);

  return(OK);
}

/*===========================================================================*
 *				do_getres				     *
 *===========================================================================*/
int
do_getres(void)
{
  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
		/* Resolution is 1/system_hz. tv_sec is 0 for sub-second resolution. */
		mp->mp_reply.m_pm_lc_time.sec = 0;
		mp->mp_reply.m_pm_lc_time.nsec = 1000000000 / system_hz;
		return(OK);
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }
}

/*===========================================================================*
 *				do_settime				     *
 *===========================================================================*/
int
do_settime(void)
{
  int s;

  /* Only root can set the system time. */
  if (mp->mp_effuid != SUPER_USER) {
      return(EPERM);
  }

  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
		s = sys_settime(m_in.m_lc_pm_time.now, m_in.m_lc_pm_time.clk_id,
			m_in.m_lc_pm_time.sec, m_in.m_lc_pm_time.nsec);
		return(s);
	case CLOCK_MONOTONIC: /* Monotonic clock cannot be changed */
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }
}

/*===========================================================================*
 *				do_time					     *
 *===========================================================================*/
int
do_time(void)
{
/* Perform the time(tp) system call (equivalent to gettimeofday with NULL tz). */
  struct timespec tv;

  (void)clock_time(&tv); /* Get current time from kernel */

  mp->mp_reply.m_pm_lc_time.sec = tv.tv_sec;
  mp->mp_reply.m_pm_lc_time.nsec = tv.tv_nsec;
  return(OK);
}

/*===========================================================================*
 *				do_stime				     *
 *===========================================================================*/
int
do_stime(void)
{
/* Perform the stime(tp) system call. Retrieve the system's uptime (ticks
 * since boot) and pass the new time in seconds at system boot to the kernel.
 */
  clock_t uptime_ticks, realtime_ticks;
  time_t current_boottime;
  int s;

  /* Only root can set the system time. */
  if (mp->mp_effuid != SUPER_USER) {
      return(EPERM);
  }

  /* Get current uptime and boottime to calculate the new boottime. */
  if ( (s=getuptime(&uptime_ticks, &realtime_ticks, &current_boottime)) != OK)
      panic("do_stime couldn't get uptime: %d", s);

  /* Calculate new boottime: new_epoch_seconds - (realtime_ticks_since_boot / system_hz) */
  current_boottime = m_in.m_lc_pm_time.sec - (realtime_ticks/system_hz);

  s = sys_stime(current_boottime);		/* Tell kernel about new boottime */
  if (s != OK)
	panic("pm: sys_stime failed: %d", s);

  return(OK);
}