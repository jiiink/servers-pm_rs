/* This file implements entry points for system profiling.
 *
 * The entry points in this file are:
 *   do_sprofile:   start/stop statistical profiling
 *
 * Changes:
 *   14 Aug, 2006  Created (Rogier Meurs)
 */

#include <minix/config.h>
#include <minix/profile.h>
#include "pm.h"
#include <sys/wait.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <signal.h>
#include "mproc.h"

/*===========================================================================*
 *				do_sprofile				     *
 *===========================================================================*/
int do_sprofile(void)
{
#if SPROFILE /* SPROFILE is a compile-time option */

  int r;

  switch(m_in.m_lc_pm_sprof.action) {

  case PROF_START:
    /* Only root can start profiling */
    if (mp->mp_effuid != SUPER_USER) {
        return EPERM;
    }
	return sys_sprof(PROF_START, (size_t)m_in.m_lc_pm_sprof.mem_size,
		m_in.m_lc_pm_sprof.freq, m_in.m_lc_pm_sprof.intr_type, who_e,
		(void *)m_in.m_lc_pm_sprof.ctl_ptr, (void *)m_in.m_lc_pm_sprof.mem_ptr);

  case PROF_STOP:
    /* Only root can stop profiling */
    if (mp->mp_effuid != SUPER_USER) {
        return EPERM;
    }
	return sys_sprof(PROF_STOP,0,0,0,0,0,0); /* Other parameters are ignored for STOP */

  default:
	return EINVAL;
  }

#else /* SPROFILE is not enabled, return ENOSYS */
	return ENOSYS;
#endif
}