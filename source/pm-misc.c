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

static const struct utsname uts_val = {
  OS_NAME,
  "noname",
  OS_RELEASE,
  OS_VERSION,
#if defined(__i386__)
  "i386",
#elif defined(__arm__)
  "evbarm",
#else
#error
#endif
};

static char *uts_tbl[] = {
#if defined(__i386__)
  "i386",
#elif defined(__arm__)
  "evbarm",
#endif
  NULL,
  uts_val.machine,
  NULL,
  uts_val.nodename,
  uts_val.release,
  uts_val.version,
  uts_val.sysname,
  NULL,
};

#if ENABLE_SYSCALL_STATS
unsigned long calls_stats[NR_PM_CALLS];
#endif

int do_sysuname(void)
{
  if (m_in.m_lc_pm_sysuname.field >= __arraycount(uts_tbl)) return EINVAL;
  char *string = uts_tbl[m_in.m_lc_pm_sysuname.field];
  if (!string) return EINVAL;

  size_t n = strlen(string) + 1;
  if (n > m_in.m_lc_pm_sysuname.len) n = m_in.m_lc_pm_sysuname.len;
  int r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
    m_in.m_lc_pm_sysuname.value, (phys_bytes)n);
  return r < 0 ? r : n;
}

int do_getsysinfo(void)
{
  if (mp->mp_effuid != 0) {
	printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
		mp->mp_endpoint, mp->mp_name);
	sys_diagctl_stacktrace(mp->mp_endpoint);
	return EPERM;
  }

  vir_bytes src_addr;
  size_t len;

  switch(m_in.m_lsys_getsysinfo.what) {
  case SI_PROC_TAB:
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
  	return EINVAL;
  }

  if (len != m_in.m_lsys_getsysinfo.size) return EINVAL;

  return sys_datacopy(SELF, src_addr, who_e, m_in.m_lsys_getsysinfo.where, len);
}

int do_getprocnr(void)
{
  if (who_e != RS_PROC_NR) {
	printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
	return EPERM;
  }

  struct mproc *rmp = find_proc(m_in.m_lsys_pm_getprocnr.pid);
  if (!rmp) return ESRCH;

  mp->mp_reply.m_pm_lsys_getprocnr.endpt = rmp->mp_endpoint;
  return OK;
}

int do_getepinfo(void)
{
  int slot;
  endpoint_t ep = m_in.m_lsys_pm_getepinfo.endpt;
  if (pm_isokendpt(ep, &slot) != OK) return ESRCH;

  struct mproc *rmp = &mproc[slot];
  mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
  mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
  mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
  mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;

  int ngroups = rmp->mp_ngroups;
  if (ngroups > m_in.m_lsys_pm_getepinfo.ngroups)
	ngroups = m_in.m_lsys_pm_getepinfo.ngroups;
  if (ngroups > 0) {
	int r = sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e,
	    m_in.m_lsys_pm_getepinfo.groups, ngroups * sizeof(gid_t));
	if (r != OK) return r;
  }

  return rmp->mp_pid;
}

int do_reboot(void)
{
  if (mp->mp_effuid != SUPER_USER) return EPERM;

  abort_flag = m_in.m_lc_pm_reboot.how;

  if (abort_flag & RB_POWERDOWN) {
	endpoint_t readclock_ep;
	if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
		message m;
		_taskcall(readclock_ep, RTCDEV_PWR_OFF, &m);
	}
  }

  check_sig(-1, SIGKILL, FALSE);
  sys_stop(INIT_PROC_NR);

  message m = {.m_type = VFS_PM_REBOOT};
  tell_vfs(&mproc[VFS_PROC_NR], &m);

  return SUSPEND;
}

int do_getsetpriority(void)
{
  int arg_which = m_in.m_lc_pm_priority.which;
  int arg_who = m_in.m_lc_pm_priority.who;
  int arg_pri = m_in.m_lc_pm_priority.prio;

  if (arg_which != PRIO_PROCESS) return EINVAL;

  struct mproc *rmp = (arg_who == 0) ? mp : find_proc(arg_who);
  if (!rmp) return ESRCH;

  if (mp->mp_effuid != SUPER_USER && mp->mp_effuid != rmp->mp_effuid &&
      mp->mp_effuid != rmp->mp_realuid) return EPERM;

  if (call_nr == PM_GETPRIORITY) {
	return rmp->mp_nice - PRIO_MIN;
  }

  if (rmp->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER) return EACCES;

  int r = sched_nice(rmp, arg_pri);
  if (r != OK) return r;

  rmp->mp_nice = arg_pri;
  return OK;
}

int do_svrctl(void)
{
  unsigned long req = m_in.m_lc_svrctl.request;
  vir_bytes ptr = m_in.m_lc_svrctl.arg;

  if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') return EINVAL;

  switch(req) {
  case OPMSETPARAM:
  case OPMGETPARAM:
  case PMSETPARAM:
  case PMGETPARAM: {
      struct sysgetenv sysgetenv;
      char search_key[64];
      char *val_start;
      size_t val_len;
      size_t copy_len;

      if (sys_datacopy(who_e, ptr, SELF, (vir_bytes) &sysgetenv,
              sizeof(sysgetenv)) != OK) return EFAULT;

      if (req == PMSETPARAM || req == OPMSETPARAM) {
  	static struct {
  	    char name[30];
  	    char value[30];
  	} local_param_overrides[2];
  	static int local_params = 0;

	if (local_params >= 2) return ENOSPC;

	if (sysgetenv.keylen <= 0 || sysgetenv.keylen >= sizeof(local_param_overrides[local_params].name) ||
	  sysgetenv.vallen <= 0 || sysgetenv.vallen >= sizeof(local_param_overrides[local_params].value)) 
	  return EINVAL;

        int s;
        if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv.key,
              SELF, (vir_bytes) local_param_overrides[local_params].name,
              sysgetenv.keylen)) != OK)
                return s;
        if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv.val,
              SELF, (vir_bytes) local_param_overrides[local_params].value,
              sysgetenv.vallen)) != OK)
                return s;
        local_param_overrides[local_params].name[sysgetenv.keylen] = '\0';
        local_param_overrides[local_params].value[sysgetenv.vallen] = '\0';

  	local_params++;
  	return OK;
      }

      if (sysgetenv.keylen == 0) {
          val_start = monitor_params;
          val_len = sizeof(monitor_params);
      } else {
    	  int p;
    	  int s;
          if (sysgetenv.keylen > sizeof(search_key)) return EINVAL;
          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv.key,
                  SELF, (vir_bytes) search_key, sysgetenv.keylen)) != OK)
              return s;

          search_key[sysgetenv.keylen-1]= '\0';
          static struct {
              char name[30];
              char value[30];
          } local_param_overrides[2];
          for(p = 0; p < 2; p++) {
          	if (!strcmp(search_key, local_param_overrides[p].name)) {
          		val_start = local_param_overrides[p].value;
          		break;
          	}
          }
          if (p >= 2 && (val_start = find_param(search_key)) == NULL) return ESRCH;
          val_len = strlen(val_start) + 1;
      }

      if (val_len > sysgetenv.vallen) return E2BIG;

      copy_len = MIN(val_len, sysgetenv.vallen);
      int s = sys_datacopy(SELF, (vir_bytes) val_start,
              who_e, (vir_bytes) sysgetenv.val, copy_len);
      return s;
  }

  default:
	return EINVAL;
  }
}

int do_getrusage(void)
{
	if (m_in.m_lc_pm_rusage.who != RUSAGE_SELF && m_in.m_lc_pm_rusage.who != RUSAGE_CHILDREN)
		return EINVAL;

	struct rusage r_usage;
	memset(&r_usage, 0, sizeof(r_usage));

	int children = (m_in.m_lc_pm_rusage.who == RUSAGE_CHILDREN);
	clock_t user_time, sys_time;

	int r;
	if (!children) {
		r = sys_times(who_e, &user_time, &sys_time, NULL, NULL);
		if (r != OK) return r;
	} else {
		user_time = mp->mp_child_utime;
		sys_time = mp->mp_child_stime;
	}

	set_rusage_times(&r_usage, user_time, sys_time);

	r = vm_getrusage(who_e, &r_usage, children);
	if (r != OK) return r;

	return sys_datacopy(SELF, (vir_bytes) &r_usage, who_e, m_in.m_lc_pm_rusage.addr, (vir_bytes) sizeof(r_usage));
}