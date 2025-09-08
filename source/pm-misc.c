/* Miscellaneous system calls.				Author: Kees J. Bot
 *								31 Mar 2000
 * The entry points into this file are:
 *   do_reboot: kill all processes, then reboot system
 *   do_getsysinfo: request copy of PM data structure  (Jorrit N. Herder)
 *   do_getprocnr: lookup endpoint by process ID
 *   do_getepinfo: get the pid/uid/gid of a process given its endpoint
 *   do_getsetpriority: get/set process priority
 *   do_svrctl: process manager control
 *   do_getrusage: obtain process resource usage information
 */

#include "pm.h"
#include <minix/callnr.h>
#include <signal.h>
#include <sys/svrctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <minix/com.h>
#include <minix/config.h>
#include <minix/sysinfo.h>
#include <minix/type.h>
#include <minix/ds.h>
#include <machine/archtypes.h>
#include <lib.h>
#include <assert.h>
#include "mproc.h"
#include "kernel/proc.h"

/* START OF COMPATIBILITY BLOCK */
struct utsname uts_val = {
  OS_NAME,		/* system name */
  "noname",		/* node/network name */
  OS_RELEASE,		/* O.S. release (e.g. 3.3.0) */
  OS_VERSION,		/* O.S. version (e.g. Minix 3.3.0 (GENERIC)) */
#if defined(__i386__)
  "i386",		/* machine (cpu) type */
#elif defined(__arm__)
  "evbarm",		/* machine (cpu) type */
#else
#error "Unknown architecture for uname -m"
#endif
};

static char *uts_tbl[] = {
#if defined(__i386__)
  "i386",		/* architecture */
#elif defined(__arm__)
  "evbarm",		/* architecture */
#else
#error "Unknown architecture for uname -m"
#endif
  NULL,			/* No kernel architecture (or same as machine) */
  uts_val.machine,
  NULL,			/* No hostname */
  uts_val.nodename,
  uts_val.release,
  uts_val.version,
  uts_val.sysname,
  NULL,			/* No bus */
};
/* END OF COMPATIBILITY BLOCK */

#if ENABLE_SYSCALL_STATS
unsigned long calls_stats[NR_PM_CALLS];
#endif

/* START OF COMPATIBILITY BLOCK */
/*===========================================================================*
 *				do_sysuname				     *
 *===========================================================================*/
int
do_sysuname(void)
{
/* Set or get uname strings. */
  int r;
  size_t n_copied;
  char *string_ptr;
  unsigned int field_index = m_in.m_lc_pm_sysuname.field;

  if (field_index >= __arraycount(uts_tbl)) return(EINVAL);

  string_ptr = uts_tbl[field_index];
  if (string_ptr == NULL)
	return EINVAL;	/* Unsupported field */

  switch (m_in.m_lc_pm_sysuname.req) {
  case 0: /* Get uname string */
	n_copied = strlen(string_ptr) + 1;
	if (n_copied > (size_t)m_in.m_lc_pm_sysuname.len) {
        n_copied = (size_t)m_in.m_lc_pm_sysuname.len;
    }
	r = sys_datacopy(SELF, (vir_bytes)string_ptr, mp->mp_endpoint,
		(vir_bytes)m_in.m_lc_pm_sysuname.value, (phys_bytes)n_copied);
	if (r < 0) return(r);
	break;

  default:
	return(EINVAL);
  }
  /* Return the number of bytes moved. */
  return(n_copied);
}
/* END OF COMPATIBILITY BLOCK */


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int
do_getsysinfo(void)
{
  vir_bytes src_addr, dst_addr;
  size_t len;
  int r;

  /* This call leaks important information. In the future, requests from
   * non-system processes should be denied.
   */
  if (mp->mp_effuid != SUPER_USER)
  {
	printf("PM: unauthorized call of do_getsysinfo by proc %d (%s)\n",
		mp->mp_endpoint, mp->mp_name);
	sys_diagctl_stacktrace(mp->mp_endpoint);
	return EPERM;
  }

  switch(m_in.m_lsys_getsysinfo.what) {
  case SI_PROC_TAB:			/* copy entire process table */
        src_addr = (vir_bytes) mproc;
        len = sizeof(struct mproc) * NR_PROCS;
        break;
#if ENABLE_SYSCALL_STATS
  case SI_CALL_STATS:
  	src_addr = (vir_bytes) calls_stats;
  	len = sizeof(calls_stats);
  	break;
#endif
  default:
  	return(EINVAL);
  }

  if (len != (size_t)m_in.m_lsys_getsysinfo.size) {
	return(EINVAL);
  }

  dst_addr = (vir_bytes)m_in.m_lsys_getsysinfo.where;
  r = sys_datacopy(SELF, src_addr, who_e, dst_addr, len);
  return r;
}

/*===========================================================================*
 *				do_getprocnr			             *
 *===========================================================================*/
int do_getprocnr(void)
{
  register struct mproc *rmp_target;

  /* This check should be replaced by per-call ACL checks.
   * Only RS is allowed to query process numbers. */
  if (who_e != RS_PROC_NR) {
	printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
	return EPERM;
  }

  if ((rmp_target = find_proc(m_in.m_lsys_pm_getprocnr.pid)) == NULL)
	return(ESRCH);

  mp->mp_reply.m_pm_lsys_getprocnr.endpt = rmp_target->mp_endpoint;
  return(OK);
}

/*===========================================================================*
 *				do_getepinfo			             *
 *===========================================================================*/
int do_getepinfo(void)
{
  struct mproc *rmp_target;
  endpoint_t ep_val;
  int r, slot_nr, ngroups_to_copy;

  ep_val = m_in.m_lsys_pm_getepinfo.endpt;
  if (pm_isokendpt(ep_val, &slot_nr) != OK)
	return(ESRCH);
  rmp_target = &mproc[slot_nr];

  /* Fill reply message with UID/GID information. */
  mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp_target->mp_realuid;
  mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp_target->mp_effuid;
  mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp_target->mp_realgid;
  mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp_target->mp_effgid;
  mp->mp_reply.m_pm_lsys_getepinfo.ngroups = rmp_target->mp_ngroups;

  /* Copy supplemental groups if requested and space allows. */
  ngroups_to_copy = rmp_target->mp_ngroups;
  if (ngroups_to_copy > m_in.m_lsys_pm_getepinfo.ngroups)
	ngroups_to_copy = m_in.m_lsys_pm_getepinfo.ngroups;

  if (ngroups_to_copy > 0) {
	if ((r = sys_datacopy(SELF, (vir_bytes)rmp_target->mp_sgroups, who_e,
	    (vir_bytes)m_in.m_lsys_pm_getepinfo.groups, (phys_bytes)ngroups_to_copy * sizeof(gid_t))) != OK)
		return(r);
  }
  return(rmp_target->mp_pid);
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int
do_reboot(void)
{
  message m;

  /* Check permission to abort the system. */
  if (mp->mp_effuid != SUPER_USER) return(EPERM);

  /* See how the system should be aborted. */
  abort_flag = m_in.m_lc_pm_reboot.how;

  /* notify readclock (some arm systems power off via RTC alarms) */
  if (abort_flag & RB_POWERDOWN) {
	endpoint_t readclock_ep;
	if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
		message rtc_m; /* no params to set, nothing we can do if it fails */
		memset(&rtc_m, 0, sizeof(rtc_m));
		rtc_m.m_type = RTCDEV_PWR_OFF; /* Assuming RTCDEV_PWR_OFF is defined and correctly used */
		_taskcall(readclock_ep, RTCDEV_PWR_OFF, &rtc_m);
	}
  }

  /* Order matters here. When VFS is told to reboot, it exits all its
   * processes, and then would be confused if they're exited again by
   * SIGKILL. So first kill, then reboot.
   */

  /* Kill all user processes except init. System processes will be handled by RS. */
  check_sig(-1, SIGKILL, FALSE /* ksig*/);
  sys_stop(INIT_PROC_NR);		   /* stop init, but keep it around */

  /* Tell VFS to reboot. */
  memset(&m, 0, sizeof(m));
  m.m_type = VFS_PM_REBOOT;

  /* Send synchronously to VFS to ensure it receives it before PM potentially crashes. */
  tell_vfs(&mproc[VFS_PROC_NR], &m);

  return(SUSPEND);			/* don't reply to caller; system will reboot */
}

/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int
do_getsetpriority(void)
{
	int r, arg_which, arg_who, arg_pri;
	struct mproc *rmp_target;

	arg_which = m_in.m_lc_pm_priority.which;
	arg_who = m_in.m_lc_pm_priority.who;
	arg_pri = m_in.m_lc_pm_priority.prio;	/* for SETPRIORITY */

	/* Code common to GETPRIORITY and SETPRIORITY. */

	/* Only support PRIO_PROCESS for now. */
	if (arg_which != PRIO_PROCESS)
		return(EINVAL);

	if (arg_who == 0) /* Target is calling process itself */
		rmp_target = mp;
	else /* Target is specified by PID */
		if ((rmp_target = find_proc(arg_who)) == NULL)
			return(ESRCH);

	/* Permission check:
	 * Only SUPER_USER or process with matching effective/real UIDs can change priority. */
	if (mp->mp_effuid != SUPER_USER &&
	    mp->mp_effuid != rmp_target->mp_effuid && mp->mp_effuid != rmp_target->mp_realuid &&
	    mp->mp_realuid != rmp_target->mp_effuid && mp->mp_realuid != rmp_target->mp_realuid)
		return EPERM;

	/* If GETPRIORITY, return current nice value. */
	if (call_nr == PM_GETPRIORITY) {
		return(rmp_target->mp_nice - PRIO_MIN);
	}

	/* We're SETPRIORITY. Check permissions to decrease nice level.
	 * Only root is allowed to reduce the nice level (i.e., increase priority). */
	if (rmp_target->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER)
		return(EACCES);

	/* The value passed in is currently between PRIO_MIN and PRIO_MAX.
	 * sched_nice maps this to the kernel's scheduling queues. */
	if ((r = sched_nice(rmp_target, arg_pri)) != OK) {
		return r;
	}

	rmp_target->mp_nice = arg_pri; /* Update PM's internal record */
	return(OK);
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
int do_svrctl(void)
{
  unsigned long req;
  int s;
  vir_bytes ptr_arg;
#define MAX_LOCAL_PARAMS 2
  static struct {
  	char name[30];
  	char value[30];
  } local_param_overrides[MAX_LOCAL_PARAMS];
  static int local_params_count = 0;

  req = m_in.m_lc_svrctl.request;
  ptr_arg = (vir_bytes)m_in.m_lc_svrctl.arg;

  /* Is the request indeed for the PM? ('M' is old and being phased out) */
  if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') return(EINVAL);

  /* Control operations local to the PM. */
  switch(req) {
  case OPMSETPARAM: /* Old/deprecated */
  case OPMGETPARAM: /* Old/deprecated */
  case PMSETPARAM:
  case PMGETPARAM: {
      struct sysgetenv sysgetenv_req;
      char search_key[64];
      char *val_start;
      size_t val_len;
      size_t copy_len;

      /* Copy sysgetenv structure to PM. */
      if (sys_datacopy(who_e, ptr_arg, SELF, (vir_bytes) &sysgetenv_req,
              sizeof(sysgetenv_req)) != OK) return(EFAULT);

      /* Set a param override? */
      if (req == PMSETPARAM || req == OPMSETPARAM) {
  	if (local_params_count >= MAX_LOCAL_PARAMS) return ENOSPC;
  	if (sysgetenv_req.keylen <= 0
  	 || sysgetenv_req.keylen >=
  	 	 sizeof(local_param_overrides[local_params_count].name)
  	 || sysgetenv_req.vallen <= 0
  	 || sysgetenv_req.vallen >=
  	 	 sizeof(local_param_overrides[local_params_count].value))
  		return EINVAL;

          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv_req.key,
            SELF, (vir_bytes) local_param_overrides[local_params_count].name,
               sysgetenv_req.keylen)) != OK)
               	return s;
          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv_req.val,
            SELF, (vir_bytes) local_param_overrides[local_params_count].value,
              sysgetenv_req.vallen)) != OK)
               	return s;
            local_param_overrides[local_params_count].name[sysgetenv_req.keylen] = '\0';
            local_param_overrides[local_params_count].value[sysgetenv_req.vallen] = '\0';

  	local_params_count++;

  	return OK;
      }

      /* PMGETPARAM: Get parameter value. */
      if (sysgetenv_req.keylen == 0) {	/* copy all parameters (monitor_params) */
          val_start = monitor_params;
          val_len = sizeof(monitor_params);
      }
      else {				/* lookup value for specific key */
      	  int p;
          /* Try to get a copy of the requested key. */
          if (sysgetenv_req.keylen > sizeof(search_key) -1 ) { /* -1 for null terminator */
              return(EINVAL);
          }
          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv_req.key,
                  SELF, (vir_bytes) search_key, sysgetenv_req.keylen)) != OK)
              return(s);

          /* Make sure key is null-terminated and lookup value.
           * First check local overrides, then boot monitor parameters. */
          search_key[sysgetenv_req.keylen]= '\0'; /* Ensure null termination */
          for(p = 0; p < local_params_count; p++) {
          	if (!strcmp(search_key, local_param_overrides[p].name)) {
          		val_start = local_param_overrides[p].value;
          		break;
          	}
          }
          if (p >= local_params_count) { /* Not found in local overrides */
              if ((val_start = find_param(search_key)) == NULL) {
                   return(ESRCH);
              }
          }
          val_len = strlen(val_start) + 1; /* Include null terminator */
      }

      /* See if it fits in the client's buffer. */
      if (val_len > sysgetenv_req.vallen)
      	return E2BIG;

      /* Value found, make the actual copy (as far as possible). */
      copy_len = MIN(val_len, sysgetenv_req.vallen);
      if ((s = sys_datacopy(SELF, (vir_bytes) val_start,
              who_e, (vir_bytes) sysgetenv_req.val, copy_len)) != OK)
          return(s);

      return OK;
  }

  default:
	return(EINVAL);
  }
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int
do_getrusage(void)
{
	clock_t user_time, sys_time;
	struct rusage r_usage;
	int r, children_flag;

	if (m_in.m_lc_pm_rusage.who != RUSAGE_SELF &&
	    m_in.m_lc_pm_rusage.who != RUSAGE_CHILDREN)
		return EINVAL;

	/*
	 * TODO: first relay the call to VFS. As is, VFS does not have any
	 * fields it can fill with meaningful values, but this may change in
	 * the future. In that case, PM would first have to use the tell_vfs()
	 * system to get those values from VFS, and do the rest here upon
	 * getting the response.
	 */

	memset(&r_usage, 0, sizeof(r_usage));

	children_flag = (m_in.m_lc_pm_rusage.who == RUSAGE_CHILDREN);

	/*
	 * Get system times. For RUSAGE_SELF, get the times for the calling
	 * process from the kernel. For RUSAGE_CHILDREN, we already have the
	 * values we should return right here (mp->mp_child_utime/stime).
	 */
	if (!children_flag) {
		if ((r = sys_times(who_e, &user_time, &sys_time, NULL,
		    NULL)) != OK)
			return r;
	} else {
		user_time = mp->mp_child_utime;
		sys_time = mp->mp_child_stime;
	}

	/* In both cases, convert from clock ticks to microseconds. */
	set_rusage_times(&r_usage, user_time, sys_time);

	/* Get additional fields from VM. */
	if ((r = vm_getrusage(who_e, &r_usage, children_flag)) != OK)
		return r;

	/* Finally copy the structure to the caller. */
	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
	    (vir_bytes)m_in.m_lc_pm_rusage.addr, (phys_bytes)sizeof(r_usage));
}