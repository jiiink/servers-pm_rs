/* This file contains some utility routines for PM.
 *
 * The entry points are:
 *   get_free_pid:	get a free process or group id
 *   find_param:	look up a boot monitor parameter
 *   find_proc:		return process pointer from pid number
 *   nice_to_priority	convert nice level to priority queue
 *   pm_isokendpt:	check the validity of an endpoint
 *   tell_vfs:		send a request to VFS on behalf of a process
 *   set_rusage_times:	store user and system times in rusage structure
 */

#include "pm.h"
#include <sys/resource.h>
#include <sys/stat.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/endpoint.h>
#include <fcntl.h>
#include <signal.h>		/* needed only because mproc.h needs it */
#include "mproc.h"

#include <minix/config.h>
#include <minix/timers.h>
#include <machine/archtypes.h>
#include "kernel/const.h"
#include "kernel/config.h"
#include "kernel/type.h"
#include "kernel/proc.h"

/*===========================================================================*
 *				get_free_pid				     *
 *===========================================================================*/
pid_t get_free_pid()
{
  static pid_t next_pid = INIT_PID + 1;		/* next pid to be assigned */
  register struct mproc *rmp;			/* check process table */
  int pid_in_use;					/* 1 if pid still free, 0 otherwise */

  /* Find a free pid for the child and put it in the table. */
  do {
	pid_in_use = 0;
	next_pid = (next_pid < NR_PIDS ? next_pid + 1 : INIT_PID + 1);
	for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++)
		if ((rmp->mp_flags & IN_USE) && (rmp->mp_pid == next_pid || rmp->mp_procgrp == next_pid)) {
			pid_in_use = 1;
			break;
		}
  } while (pid_in_use);
  return(next_pid);
}

/*===========================================================================*
 *				find_param				     *
 *===========================================================================*/
char *
find_param(const char *name)
{
  register const char *namep;
  register char *envp;

  /* Monitor parameters are stored as "VAR=VALUE\0VAR2=VALUE2\0\0" */
  for (envp = (char *) monitor_params; *envp != '\0';) {
	for (namep = name; *namep != '\0' && *namep == *envp; namep++, envp++)
		;
	if (*namep == '\0' && *envp == '=')
		return(envp + 1); /* Found match, return pointer to value */
	while (*envp++ != '\0') /* Skip to next parameter */
		;
  }
  return(NULL); /* Parameter not found */
}

/*===========================================================================*
 *				find_proc  				     *
 *===========================================================================*/
struct mproc *find_proc(pid_t lpid)
{
  register struct mproc *rmp;

  for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++)
	if ((rmp->mp_flags & IN_USE) && rmp->mp_pid == lpid)
		return(rmp);

  return(NULL);
}

/*===========================================================================*
 *				nice_to_priority			     *
 *===========================================================================*/
int nice_to_priority(int nice_val, unsigned* new_q)
{
	if (nice_val < PRIO_MIN || nice_val > PRIO_MAX) return(EINVAL);

	/* Map nice_val from [PRIO_MIN, PRIO_MAX] to [MAX_USER_Q, MIN_USER_Q].
	 * Lower nice_val means higher priority (lower queue number).
	 */
	*new_q = MAX_USER_Q + (unsigned int)((nice_val - PRIO_MIN) * (MIN_USER_Q - MAX_USER_Q + 1)) /
	    (unsigned int)(PRIO_MAX - PRIO_MIN + 1);

	/* Neither of these should ever happen if calculation is correct, but defensive check. */
	if (*new_q < (unsigned int)MAX_USER_Q) *new_q = (unsigned int)MAX_USER_Q;
	if (*new_q > (unsigned int)MIN_USER_Q) *new_q = (unsigned int)MIN_USER_Q;

	return (OK);
}

/*===========================================================================*
 *				pm_isokendpt			 	     *
 *===========================================================================*/
int pm_isokendpt(endpoint_t endpoint, int *proc)
{
	*proc = _ENDPOINT_P(endpoint); /* Extract process number from endpoint */
	if (*proc < 0 || *proc >= NR_PROCS)
		return EINVAL; /* Invalid process number range */
	if (mproc[*proc].mp_endpoint != endpoint)
		return EDEADEPT; /* Endpoint mismatch, likely dead process */
	if (!(mproc[*proc].mp_flags & IN_USE))
		return EDEADEPT; /* Slot not in use */
	return OK;
}

/*===========================================================================*
 *				tell_vfs			 	     *
 *===========================================================================*/
void tell_vfs(struct mproc *rmp, message *m_ptr)
{
/* Send a request to VFS, without blocking.
 */
  int r;

  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL))
	panic("tell_vfs: process %d is not idle when sending type %d", rmp->mp_endpoint, m_ptr->m_type);

  r = asynsend3(VFS_PROC_NR, m_ptr, AMF_NOREPLY);
  if (r != OK)
  	panic("unable to send to VFS: %d for message type %d", r, m_ptr->m_type);

  rmp->mp_flags |= VFS_CALL; /* Mark process as waiting for VFS reply */
}

/*===========================================================================*
 *				set_rusage_times		 	     *
 *===========================================================================*/
void
set_rusage_times(struct rusage * r_usage, clock_t user_time, clock_t sys_time)
{
	u64_t usec;

	/* Convert user time from ticks to microseconds. */
	usec = (u64_t)user_time * 1000000 / sys_hz();
	r_usage->ru_utime.tv_sec = usec / 1000000;
	r_usage->ru_utime.tv_usec = usec % 1000000;

	/* Convert system time from ticks to microseconds. */
	usec = (u64_t)sys_time * 1000000 / sys_hz();
	r_usage->ru_stime.tv_sec = usec / 1000000;
	r_usage->ru_stime.tv_usec = usec % 1000000;
}