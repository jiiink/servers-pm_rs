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
#include <errno.h>
#include "mproc.h"

/* Constants for time validation */
#define NSEC_PER_SEC	1000000000L
#define SEC_MIN_VALUE	0
#define SEC_MAX_VALUE	LONG_MAX

/*===========================================================================*
 *				do_gettime				     *
 *===========================================================================*/
int
do_gettime(void)
{
  clock_t ticks, realtime, clock;
  time_t boottime;
  int s;

  if ( (s=getuptime(&ticks, &realtime, &boottime)) != OK) {
  	panic("do_gettime couldn't get uptime: %d", s);
  }

  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
		clock = realtime;
		break;
	case CLOCK_MONOTONIC:
		clock = ticks;
		break;
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }

  mp->mp_reply.m_pm_lc_time.sec = boottime + (clock / system_hz);
  mp->mp_reply.m_pm_lc_time.nsec =
	(uint32_t) ((clock % system_hz) * 1000000000ULL / system_hz);

  return OK;
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
		/* tv_sec is always 0 since system_hz is an int */
		mp->mp_reply.m_pm_lc_time.sec = 0;
		mp->mp_reply.m_pm_lc_time.nsec = 1000000000 / system_hz;
		return OK;
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
  time_t sec;
  long nsec;

  if (mp->mp_effuid != SUPER_USER) {
      return EPERM;
  }

  /* Validate input parameters */
  sec = m_in.m_lc_pm_time.sec;
  nsec = m_in.m_lc_pm_time.nsec;

  if (sec < SEC_MIN_VALUE || sec > SEC_MAX_VALUE) {
      return EINVAL;
  }

  if (nsec < 0 || nsec >= NSEC_PER_SEC) {
      return EINVAL;
  }

  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
		s = sys_settime(m_in.m_lc_pm_time.now, m_in.m_lc_pm_time.clk_id,
			sec, nsec);
		return s;
	case CLOCK_MONOTONIC: /* monotonic cannot be changed */
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
/* Perform the time(tp) system call. */
  struct timespec tv;

  (void)clock_time(&tv);

  mp->mp_reply.m_pm_lc_time.sec = tv.tv_sec;
  mp->mp_reply.m_pm_lc_time.nsec = tv.tv_nsec;
  return OK;
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
  clock_t uptime, realtime;
  time_t boottime;
  time_t new_time;
  int s;

  if (mp->mp_effuid != SUPER_USER) {
      return EPERM;
  }

  new_time = m_in.m_lc_pm_time.sec;

  /* Validate input time */
  if (new_time < SEC_MIN_VALUE || new_time > SEC_MAX_VALUE) {
      return EINVAL;
  }

  if ( (s=getuptime(&uptime, &realtime, &boottime)) != OK) {
      panic("do_stime couldn't get uptime: %d", s);
  }

  boottime = new_time - (realtime/system_hz);

  s = sys_stime(boottime);		/* Tell kernel about boottime */
  if (s != OK) {
	panic("pm: sys_stime failed: %d", s);
  }

  return OK;
}
