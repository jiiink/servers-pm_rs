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

#define NSEC_PER_SEC 1000000000ULL

/*===========================================================================*
 *				do_gettime				     *
 *===========================================================================*/
int do_gettime(void)
{
  clock_t ticks, realtime, clk;
  time_t boottime;
  int s;

  s = getuptime(&ticks, &realtime, &boottime);
  if (s != OK) panic("do_gettime couldn't get uptime: %d", s);

  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
		clk = realtime;
		break;
	case CLOCK_MONOTONIC:
		clk = ticks;
		break;
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }

  mp->mp_reply.m_pm_lc_time.sec = boottime + (clk / system_hz);
  mp->mp_reply.m_pm_lc_time.nsec =
	(uint32_t)(((clk % system_hz) * NSEC_PER_SEC) / (unsigned long)system_hz);

  return OK;
}

/*===========================================================================*
 *				do_getres				     *
 *===========================================================================*/
int do_getres(void)
{
  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
		mp->mp_reply.m_pm_lc_time.sec = 0;
		mp->mp_reply.m_pm_lc_time.nsec =
			(uint32_t)(NSEC_PER_SEC / (unsigned long)system_hz);
		return OK;
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }
}

/*===========================================================================*
 *				do_settime				     *
 *===========================================================================*/
int do_settime(void)
{
  int s;

  if (mp->mp_effuid != SUPER_USER) return EPERM;

  switch (m_in.m_lc_pm_time.clk_id) {
	case CLOCK_REALTIME:
		s = sys_settime(m_in.m_lc_pm_time.now, m_in.m_lc_pm_time.clk_id,
			m_in.m_lc_pm_time.sec, m_in.m_lc_pm_time.nsec);
		return s;
	case CLOCK_MONOTONIC: /* monotonic cannot be changed */
	default:
		return EINVAL; /* invalid/unsupported clock_id */
  }
}

/*===========================================================================*
 *				do_time					     *
 *===========================================================================*/
int do_time(void)
{
  struct timespec tv;
  int r = clock_time(&tv);
  if (r != OK) panic("do_time couldn't get time: %d", r);

  mp->mp_reply.m_pm_lc_time.sec = tv.tv_sec;
  mp->mp_reply.m_pm_lc_time.nsec = tv.tv_nsec;
  return OK;
}

/*===========================================================================*
 *				do_stime				     *
 *===========================================================================*/
int do_stime(void)
{
  /* Perform the stime(tp) system call. Retrieve the system's uptime (ticks
   * since boot) and pass the new time in seconds at system boot to the kernel.
   */
  clock_t uptime, realtime;
  time_t boottime;
  int s;

  if (mp->mp_effuid != SUPER_USER) return EPERM;

  s = getuptime(&uptime, &realtime, &boottime);
  if (s != OK) panic("do_stime couldn't get uptime: %d", s);

  boottime = m_in.m_lc_pm_time.sec - (realtime / system_hz);

  s = sys_stime(boottime); /* Tell kernel about boottime */
  if (s != OK) panic("pm: sys_stime failed: %d", s);

  return OK;
}