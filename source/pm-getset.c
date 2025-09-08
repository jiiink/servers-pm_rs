#include "pm.h"
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <limits.h>
#include <minix/com.h>
#include <signal.h>
#include <string.h>
#include "mproc.h"

int do_get(void)
{
  struct mproc *rmp = mp;

  switch (call_nr) {
	case PM_GETGROUPS:
	{
		int ngroups = m_in.m_lc_pm_groups.num;

		if (ngroups < 0 || ngroups > NGROUPS_MAX) return EINVAL;

		if (ngroups == 0) return rmp->mp_ngroups;

		if (ngroups < rmp->mp_ngroups) return EINVAL;

		if (m_in.m_lc_pm_groups.ptr == 0) return EFAULT;

		size_t nbytes = (size_t)ngroups * sizeof(rmp->mp_sgroups[0]);
		int r = sys_datacopy(SELF, (vir_bytes) rmp->mp_sgroups, who_e,
			m_in.m_lc_pm_groups.ptr, nbytes);
		if (r != OK) return r;

		return rmp->mp_ngroups;
	}
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
	{
		pid_t p = m_in.m_lc_pm_getsid.pid;
		struct mproc *target = p ? find_proc(p) : &mproc[who_p];
		if (!target) return ESRCH;
		return target->mp_procgrp;
	}
	case PM_ISSETUGID:
		return (rmp->mp_flags & TAINTED) ? 1 : 0;

	default:
		return EINVAL;
  }
}

int do_set(void)
{
  struct mproc *rmp = mp;
  message m;
  memset(&m, 0, sizeof(m));

  switch (call_nr) {
	case PM_SETUID:
	{
		uid_t uid = m_in.m_lc_pm_setuid.uid;
		if (rmp->mp_realuid != uid && rmp->mp_effuid != SUPER_USER)
			return EPERM;

		rmp->mp_realuid = uid;
		rmp->mp_effuid = uid;
		rmp->mp_svuid = uid;

		m.m_type = VFS_PM_SETUID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effuid;
		m.VFS_PM_RID = rmp->mp_realuid;
		break;
	}
	case PM_SETEUID:
	{
		uid_t uid = m_in.m_lc_pm_setuid.uid;
		if (rmp->mp_realuid != uid && rmp->mp_svuid != uid &&
		    rmp->mp_effuid != SUPER_USER)
			return EPERM;

		rmp->mp_effuid = uid;

		m.m_type = VFS_PM_SETUID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effuid;
		m.VFS_PM_RID = rmp->mp_realuid;
		break;
	}
	case PM_SETGID:
	{
		gid_t gid = m_in.m_lc_pm_setgid.gid;
		if (rmp->mp_realgid != gid && rmp->mp_effuid != SUPER_USER)
			return EPERM;

		rmp->mp_realgid = gid;
		rmp->mp_effgid = gid;
		rmp->mp_svgid = gid;

		m.m_type = VFS_PM_SETGID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effgid;
		m.VFS_PM_RID = rmp->mp_realgid;
		break;
	}
	case PM_SETEGID:
	{
		gid_t gid = m_in.m_lc_pm_setgid.gid;
		if (rmp->mp_realgid != gid && rmp->mp_svgid != gid &&
		    rmp->mp_effuid != SUPER_USER)
			return EPERM;

		rmp->mp_effgid = gid;

		m.m_type = VFS_PM_SETGID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effgid;
		m.VFS_PM_RID = rmp->mp_realgid;
		break;
	}
	case PM_SETGROUPS:
	{
		int ngroups = m_in.m_lc_pm_groups.num;

		if (rmp->mp_effuid != SUPER_USER) return EPERM;
		if (ngroups < 0 || ngroups > NGROUPS_MAX) return EINVAL;
		if (ngroups > 0 && m_in.m_lc_pm_groups.ptr == 0) return EFAULT;

		size_t nbytes = (size_t)ngroups * sizeof(rmp->mp_sgroups[0]);
		int r = sys_datacopy(who_e, m_in.m_lc_pm_groups.ptr, SELF,
			(vir_bytes) rmp->mp_sgroups, nbytes);
		if (r != OK) return r;

		for (int i = 0; i < ngroups; i++) {
			if (rmp->mp_sgroups[i] > GID_MAX) return EINVAL;
		}
		for (int i = ngroups; i < NGROUPS_MAX; i++) rmp->mp_sgroups[i] = 0;

		rmp->mp_ngroups = ngroups;

		m.m_type = VFS_PM_SETGROUPS;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_GROUP_NO = rmp->mp_ngroups;
		m.VFS_PM_GROUP_ADDR = (char *) rmp->mp_sgroups;
		break;
	}
	case PM_SETSID:
		if (rmp->mp_procgrp == rmp->mp_pid) return EPERM;

		rmp->mp_procgrp = rmp->mp_pid;

		m.m_type = VFS_PM_SETSID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		break;

	default:
		return EINVAL;
  }

  tell_vfs(rmp, &m);
  return SUSPEND;
}