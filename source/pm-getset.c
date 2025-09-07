/* This file handles the 6 system calls that get and set uids and gids.
 * It also handles getpid(), setsid(), and getpgrp().
 */

#include "pm.h"
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <limits.h>
#include <minix/com.h>
#include <signal.h>
#include "mproc.h"

/* Function prototypes */
static int validate_groups_params(int ngroups);
static int copy_groups_to_user(gid_t *groups, int ngroups, vir_bytes ptr);
static int copy_groups_from_user(gid_t *groups, int ngroups, vir_bytes ptr);
static int validate_groups_values(gid_t *groups, int ngroups);

/*===========================================================================*
 *				validate_groups_params			     *
 *===========================================================================*/
static int validate_groups_params(int ngroups)
{
	if (ngroups > NGROUPS_MAX || ngroups < 0) {
		return EINVAL;
	}
	return OK;
}

/*===========================================================================*
 *				copy_groups_to_user			     *
 *===========================================================================*/
static int copy_groups_to_user(gid_t *groups, int ngroups, vir_bytes ptr)
{
	if (groups == NULL || ngroups <= 0 || ptr == 0) {
		return EINVAL;
	}

	return sys_datacopy(SELF, (vir_bytes)groups, who_e, ptr,
	                    ngroups * sizeof(gid_t));
}

/*===========================================================================*
 *				copy_groups_from_user			     *
 *===========================================================================*/
static int copy_groups_from_user(gid_t *groups, int ngroups, vir_bytes ptr)
{
	if (groups == NULL || ngroups <= 0 || ptr == 0) {
		return EFAULT;
	}

	return sys_datacopy(who_e, ptr, SELF, (vir_bytes)groups,
	                    ngroups * sizeof(gid_t));
}

/*===========================================================================*
 *				validate_groups_values			     *
 *===========================================================================*/
static int validate_groups_values(gid_t *groups, int ngroups)
{
	int i;

	if (groups == NULL) {
		return EINVAL;
	}

	for (i = 0; i < ngroups; i++) {
		if (groups[i] > GID_MAX) {
			return EINVAL;
		}
	}
	return OK;
}

/*===========================================================================*
 *				do_get					     *
 *===========================================================================*/
int do_get(void)
{
	struct mproc *rmp = mp;
	struct mproc *target;
	int r;
	int ngroups;
	pid_t pid;

	switch (call_nr) {
	case PM_GETGROUPS:
		ngroups = m_in.m_lc_pm_groups.num;
		r = validate_groups_params(ngroups);
		if (r != OK) {
			return r;
		}

		if (ngroups == 0) {
			return rmp->mp_ngroups;
		}

		if (ngroups < rmp->mp_ngroups) {
			return EINVAL;
		}

		r = copy_groups_to_user(rmp->mp_sgroups, rmp->mp_ngroups,
		                       m_in.m_lc_pm_groups.ptr);
		if (r != OK) {
			return r;
		}

		return rmp->mp_ngroups;

	case PM_GETUID:
		rmp->mp_reply.m_pm_lc_getuid.euid = rmp->mp_effuid;
		return rmp->mp_realuid;

	case PM_GETGID:
		rmp->mp_reply.m_pm_lc_getgid.egid = rmp->mp_effgid;
		return rmp->mp_realgid;

	case PM_GETPID:
		rmp->mp_reply.m_pm_lc_getpid.parent_pid = 
			mproc[rmp->mp_parent].mp_pid;
		return mproc[who_p].mp_pid;

	case PM_GETPGRP:
		return rmp->mp_procgrp;

	case PM_GETSID:
		pid = m_in.m_lc_pm_getsid.pid;
		target = pid ? find_proc(pid) : &mproc[who_p];
		if (target == NULL) {
			return ESRCH;
		}
		return target->mp_procgrp;

	case PM_ISSETUGID:
		return !!(rmp->mp_flags & TAINTED);

	default:
		return EINVAL;
	}
}

/*===========================================================================*
 *				do_set					     *
 *===========================================================================*/
int do_set(void)
{
	struct mproc *rmp = mp;
	message m;
	int r, i;
	int ngroups;
	uid_t uid;
	gid_t gid;

	memset(&m, 0, sizeof(m));

	switch (call_nr) {
	case PM_SETUID:
		uid = m_in.m_lc_pm_setuid.uid;
		if (rmp->mp_realuid != uid && rmp->mp_effuid != SUPER_USER) {
			return EPERM;
		}

		rmp->mp_realuid = uid;
		rmp->mp_effuid = uid;
		rmp->mp_svuid = uid;

		m.m_type = VFS_PM_SETUID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effuid;
		m.VFS_PM_RID = rmp->mp_realuid;
		break;

	case PM_SETEUID:
		uid = m_in.m_lc_pm_setuid.uid;
		if (rmp->mp_realuid != uid && rmp->mp_svuid != uid &&
		    rmp->mp_effuid != SUPER_USER) {
			return EPERM;
		}

		rmp->mp_effuid = uid;

		m.m_type = VFS_PM_SETUID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effuid;
		m.VFS_PM_RID = rmp->mp_realuid;
		break;

	case PM_SETGID:
		gid = m_in.m_lc_pm_setgid.gid;
		if (rmp->mp_realgid != gid && rmp->mp_effuid != SUPER_USER) {
			return EPERM;
		}

		rmp->mp_realgid = gid;
		rmp->mp_effgid = gid;
		rmp->mp_svgid = gid;

		m.m_type = VFS_PM_SETGID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effgid;
		m.VFS_PM_RID = rmp->mp_realgid;
		break;

	case PM_SETEGID:
		gid = m_in.m_lc_pm_setgid.gid;
		if (rmp->mp_realgid != gid && rmp->mp_svgid != gid &&
		    rmp->mp_effuid != SUPER_USER) {
			return EPERM;
		}

		rmp->mp_effgid = gid;

		m.m_type = VFS_PM_SETGID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effgid;
		m.VFS_PM_RID = rmp->mp_realgid;
		break;

	case PM_SETGROUPS:
		if (rmp->mp_effuid != SUPER_USER) {
			return EPERM;
		}

		ngroups = m_in.m_lc_pm_groups.num;
		r = validate_groups_params(ngroups);
		if (r != OK) {
			return r;
		}

		if (ngroups > 0) {
			r = copy_groups_from_user(rmp->mp_sgroups, ngroups,
			                          m_in.m_lc_pm_groups.ptr);
			if (r != OK) {
				return r;
			}

			r = validate_groups_values(rmp->mp_sgroups, ngroups);
			if (r != OK) {
				return r;
			}
		}

		/* Clear unused groups */
		for (i = ngroups; i < NGROUPS_MAX; i++) {
			rmp->mp_sgroups[i] = 0;
		}
		rmp->mp_ngroups = ngroups;

		m.m_type = VFS_PM_SETGROUPS;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_GROUP_NO = rmp->mp_ngroups;
		m.VFS_PM_GROUP_ADDR = (char *)rmp->mp_sgroups;
		break;

	case PM_SETSID:
		if (rmp->mp_procgrp == rmp->mp_pid) {
			return EPERM;
		}

		rmp->mp_procgrp = rmp->mp_pid;

		m.m_type = VFS_PM_SETSID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		break;

	default:
		return EINVAL;
	}

	/* Send request to VFS */
	tell_vfs(rmp, &m);
	return SUSPEND;
}