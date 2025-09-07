/* Miscellaneous system calls. */

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

/* System identification strings */
struct utsname uts_val = {
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

#define MAX_LOCAL_PARAMS 2
static struct {
	char name[30];
	char value[30];
} local_param_overrides[MAX_LOCAL_PARAMS];
static int local_params = 0;

/* Function prototypes */
static int handle_setparam(struct sysgetenv *sysgetenv);
static int handle_getparam(struct sysgetenv *sysgetenv);
static int copy_param_value(const char *val_start, size_t val_len,
                            struct sysgetenv *sysgetenv);

/*===========================================================================*
 *				do_sysuname				     *
 *===========================================================================*/
int do_sysuname(void)
{
	int r;
	size_t n;
	char *string;
	unsigned int field;

	field = m_in.m_lc_pm_sysuname.field;
	if (field >= __arraycount(uts_tbl)) {
		return EINVAL;
	}

	string = uts_tbl[field];
	if (string == NULL) {
		return EINVAL;
	}

	/* Only support getting values */
	if (m_in.m_lc_pm_sysuname.req != 0) {
		return EINVAL;
	}

	/* Copy string to user */
	n = strlen(string) + 1;
	if (n > m_in.m_lc_pm_sysuname.len) {
		n = m_in.m_lc_pm_sysuname.len;
	}

	r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
	                m_in.m_lc_pm_sysuname.value, (phys_bytes)n);
	if (r < 0) {
		return r;
	}

	return (int)n;
}

/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int do_getsysinfo(void)
{
	vir_bytes src_addr, dst_addr;
	size_t len;

	/* Check permissions */
	if (mp->mp_effuid != 0) {
		printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
		       mp->mp_endpoint, mp->mp_name);
		sys_diagctl_stacktrace(mp->mp_endpoint);
		return EPERM;
	}

	/* Get source address and length based on request */
	switch (m_in.m_lsys_getsysinfo.what) {
	case SI_PROC_TAB:
		src_addr = (vir_bytes)mproc;
		len = sizeof(struct mproc) * NR_PROCS;
		break;
#if ENABLE_SYSCALL_STATS
	case SI_CALL_STATS:
		src_addr = (vir_bytes)calls_stats;
		len = sizeof(calls_stats);
		break;
#endif
	default:
		return EINVAL;
	}

	/* Verify size matches */
	if (len != m_in.m_lsys_getsysinfo.size) {
		return EINVAL;
	}

	/* Copy data to caller */
	dst_addr = m_in.m_lsys_getsysinfo.where;
	return sys_datacopy(SELF, src_addr, who_e, dst_addr, len);
}

/*===========================================================================*
 *				do_getprocnr			             *
 *===========================================================================*/
int do_getprocnr(void)
{
	struct mproc *rmp;

	/* Check permissions */
	if (who_e != RS_PROC_NR) {
		printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
		return EPERM;
	}

	/* Find process */
	rmp = find_proc(m_in.m_lsys_pm_getprocnr.pid);
	if (rmp == NULL) {
		return ESRCH;
	}

	mp->mp_reply.m_pm_lsys_getprocnr.endpt = rmp->mp_endpoint;
	return OK;
}

/*===========================================================================*
 *				do_getepinfo			             *
 *===========================================================================*/
int do_getepinfo(void)
{
	struct mproc *rmp;
	endpoint_t ep;
	int r, slot, ngroups;

	ep = m_in.m_lsys_pm_getepinfo.endpt;
	if (pm_isokendpt(ep, &slot) != OK) {
		return ESRCH;
	}

	rmp = &mproc[slot];

	/* Fill reply with process info */
	mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
	mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
	mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
	mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;
	mp->mp_reply.m_pm_lsys_getepinfo.ngroups = ngroups = rmp->mp_ngroups;

	/* Copy supplementary groups if requested */
	if (ngroups > m_in.m_lsys_pm_getepinfo.ngroups) {
		ngroups = m_in.m_lsys_pm_getepinfo.ngroups;
	}

	if (ngroups > 0) {
		r = sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e,
		                m_in.m_lsys_pm_getepinfo.groups, 
		                ngroups * sizeof(gid_t));
		if (r != OK) {
			return r;
		}
	}

	return rmp->mp_pid;
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int do_reboot(void)
{
	message m;
	endpoint_t readclock_ep;

	/* Check permissions */
	if (mp->mp_effuid != SUPER_USER) {
		return EPERM;
	}

	/* Save abort flag */
	abort_flag = m_in.m_lc_pm_reboot.how;

	/* Notify readclock for powerdown */
	if (abort_flag & RB_POWERDOWN) {
		if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
			message clock_m;
			memset(&clock_m, 0, sizeof(clock_m));
			_taskcall(readclock_ep, RTCDEV_PWR_OFF, &clock_m);
		}
	}

	/* Kill all users except init */
	check_sig(-1, SIGKILL, FALSE);

	/* Stop init */
	sys_stop(INIT_PROC_NR);

	/* Tell VFS to reboot */
	memset(&m, 0, sizeof(m));
	m.m_type = VFS_PM_REBOOT;
	tell_vfs(&mproc[VFS_PROC_NR], &m);

	return SUSPEND;
}

/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int do_getsetpriority(void)
{
	int r, arg_which, arg_who, arg_pri;
	struct mproc *rmp;

	arg_which = m_in.m_lc_pm_priority.which;
	arg_who = m_in.m_lc_pm_priority.who;
	arg_pri = m_in.m_lc_pm_priority.prio;

	/* Only support PRIO_PROCESS */
	if (arg_which != PRIO_PROCESS) {
		return EINVAL;
	}

	/* Find target process */
	if (arg_who == 0) {
		rmp = mp;
	} else {
		rmp = find_proc(arg_who);
		if (rmp == NULL) {
			return ESRCH;
		}
	}

	/* Check permissions */
	if (mp->mp_effuid != SUPER_USER &&
	    mp->mp_effuid != rmp->mp_effuid && 
	    mp->mp_effuid != rmp->mp_realuid) {
		return EPERM;
	}

	/* Handle GETPRIORITY */
	if (call_nr == PM_GETPRIORITY) {
		return rmp->mp_nice - PRIO_MIN;
	}

	/* Handle SETPRIORITY - check permissions */
	if (rmp->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER) {
		return EACCES;
	}

	/* Set new priority */
	r = sched_nice(rmp, arg_pri);
	if (r != OK) {
		return r;
	}

	rmp->mp_nice = arg_pri;
	return OK;
}

/*===========================================================================*
 *				handle_setparam				     *
 *===========================================================================*/
static int handle_setparam(struct sysgetenv *sysgetenv)
{
	int s;

	if (sysgetenv == NULL) {
		return EINVAL;
	}

	/* Check for available space */
	if (local_params >= MAX_LOCAL_PARAMS) {
		return ENOSPC;
	}

	/* Validate lengths */
	if (sysgetenv->keylen <= 0 ||
	    sysgetenv->keylen >= sizeof(local_param_overrides[0].name) ||
	    sysgetenv->vallen <= 0 ||
	    sysgetenv->vallen >= sizeof(local_param_overrides[0].value)) {
		return EINVAL;
	}

	/* Copy key */
	s = sys_datacopy(who_e, (vir_bytes)sysgetenv->key,
	                SELF, (vir_bytes)local_param_overrides[local_params].name,
	                sysgetenv->keylen);
	if (s != OK) {
		return s;
	}

	/* Copy value */
	s = sys_datacopy(who_e, (vir_bytes)sysgetenv->val,
	                SELF, (vir_bytes)local_param_overrides[local_params].value,
	                sysgetenv->vallen);
	if (s != OK) {
		return s;
	}

	/* Null-terminate strings */
	local_param_overrides[local_params].name[sysgetenv->keylen] = '\0';
	local_param_overrides[local_params].value[sysgetenv->vallen] = '\0';

	local_params++;
	return OK;
}

/*===========================================================================*
 *				handle_getparam				     *
 *===========================================================================*/
static int handle_getparam(struct sysgetenv *sysgetenv)
{
	char search_key[64];
	const char *val_start;
	size_t val_len;
	int s, p;

	if (sysgetenv == NULL) {
		return EINVAL;
	}

	/* Get all parameters or specific key */
	if (sysgetenv->keylen == 0) {
		val_start = monitor_params;
		val_len = sizeof(monitor_params);
	} else {
		/* Copy key from user */
		if (sysgetenv->keylen > sizeof(search_key)) {
			return EINVAL;
		}

		s = sys_datacopy(who_e, (vir_bytes)sysgetenv->key,
		                SELF, (vir_bytes)search_key, sysgetenv->keylen);
		if (s != OK) {
			return s;
		}

		/* Null-terminate key */
		search_key[sysgetenv->keylen - 1] = '\0';

		/* Check local overrides first */
		val_start = NULL;
		for (p = 0; p < local_params; p++) {
			if (strcmp(search_key, local_param_overrides[p].name) == 0) {
				val_start = local_param_overrides[p].value;
				break;
			}
		}

		/* Check global params if not found */
		if (val_start == NULL) {
			val_start = find_param(search_key);
			if (val_start == NULL) {
				return ESRCH;
			}
		}

		val_len = strlen(val_start) + 1;
	}

	return copy_param_value(val_start, val_len, sysgetenv);
}

/*===========================================================================*
 *				copy_param_value			     *
 *===========================================================================*/
static int copy_param_value(const char *val_start, size_t val_len,
                            struct sysgetenv *sysgetenv)
{
	size_t copy_len;

	if (val_start == NULL || sysgetenv == NULL) {
		return EINVAL;
	}

	/* Check buffer size */
	if (val_len > sysgetenv->vallen) {
		return E2BIG;
	}

	/* Copy value to user */
	copy_len = MIN(val_len, sysgetenv->vallen);
	return sys_datacopy(SELF, (vir_bytes)val_start,
	                   who_e, (vir_bytes)sysgetenv->val, copy_len);
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
int do_svrctl(void)
{
	unsigned long req;
	vir_bytes ptr;
	struct sysgetenv sysgetenv;
	int s;

	req = m_in.m_lc_svrctl.request;
	ptr = m_in.m_lc_svrctl.arg;

	/* Check request group */
	if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') {
		return EINVAL;
	}

	/* Handle request */
	switch (req) {
	case OPMSETPARAM:
	case PMSETPARAM:
		/* Copy sysgetenv structure */
		s = sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sysgetenv,
		                sizeof(sysgetenv));
		if (s != OK) {
			return EFAULT;
		}
		return handle_setparam(&sysgetenv);

	case OPMGETPARAM:
	case PMGETPARAM:
		/* Copy sysgetenv structure */
		s = sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sysgetenv,
		                sizeof(sysgetenv));
		if (s != OK) {
			return EFAULT;
		}
		return handle_getparam(&sysgetenv);

	default:
		return EINVAL;
	}
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int do_getrusage(void)
{
	clock_t user_time, sys_time;
	struct rusage r_usage;
	int r, children;

	/* Validate 'who' parameter */
	if (m_in.m_lc_pm_rusage.who != RUSAGE_SELF &&
	    m_in.m_lc_pm_rusage.who != RUSAGE_CHILDREN) {
		return EINVAL;
	}

	children = (m_in.m_lc_pm_rusage.who == RUSAGE_CHILDREN);

	/* Initialize rusage structure */
	memset(&r_usage, 0, sizeof(r_usage));

	/* Get times */
	if (!children) {
		r = sys_times(who_e, &user_time, &sys_time, NULL, NULL);
		if (r != OK) {
			return r;
		}
	} else {
		user_time = mp->mp_child_utime;
		sys_time = mp->mp_child_stime;
	}

	/* Set times in rusage */
	set_rusage_times(&r_usage, user_time, sys_time);

	/* Get VM statistics */
	r = vm_getrusage(who_e, &r_usage, children);
	if (r != OK) {
		return r;
	}

	/* Copy to user */
	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
	                   m_in.m_lc_pm_rusage.addr, sizeof(r_usage));
}