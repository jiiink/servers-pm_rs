/* This file handles the 6 system calls that get and set uids and gids.
 * It also handles getpid(), setsid(), and getpgrp().  The code for each
 * one is so tiny that it hardly seemed worthwhile to make each a separate
 * function.
 */

#include "pm.h"
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <limits.h>
#include <minix/com.h>
#include <signal.h>
#include "mproc.h"

/*===========================================================================*
 *				do_get					     *
 *===========================================================================*/
int
do_get(void)
{
/* Handle PM_GETUID, PM_GETGID, PM_GETGROUPS, PM_GETPID, PM_GETPGRP, PM_GETSID,
 * PM_ISSETUGID.
 */
  register struct mproc *rmp = mp;
  int r = OK;
  int ngroups_requested;

  switch(call_nr) {
	case PM_GETGROUPS:
		ngroups_requested = m_in.m_lc_pm_groups.num;
		if (ngroups_requested > NGROUPS_MAX || ngroups_requested < 0)
			return(EINVAL);

		if (ngroups_requested == 0) {
			r = rmp->mp_ngroups;
			break;
		}

		if (ngroups_requested < rmp->mp_ngroups) {
			/* Asking for less groups than available. POSIX specifies this
			 * is an error. */
			return(EINVAL);
		}

		/* Copy supplemental groups to user space. */
		r = sys_datacopy(SELF, (vir_bytes) rmp->mp_sgroups, who_e,
			(vir_bytes)m_in.m_lc_pm_groups.ptr,
			(phys_bytes)ngroups_requested * sizeof(gid_t));
		if (r != OK)
			return(r);

		r = rmp->mp_ngroups; /* Return number of groups actually copied */
		break;

	case PM_GETUID:
		mp->mp_reply.m_pm_lc_getuid.euid = rmp->mp_effuid;
		r = rmp->mp_realuid;
		break;

	case PM_GETGID:
		mp->mp_reply.m_pm_lc_getgid.egid = rmp->mp_effgid;
		r = rmp->mp_realgid;
		break;

	case PM_GETPID:
		mp->mp_reply.m_pm_lc_getpid.parent_pid = mproc[rmp->mp_parent].mp_pid;
		r = rmp->mp_pid;
		break;

	case PM_GETPGRP:
		r = rmp->mp_procgrp;
		break;

	case PM_GETSID:
	{
		struct mproc *target_mp;
		pid_t p_id = m_in.m_lc_pm_getsid.pid;
		target_mp = p_id ? find_proc(p_id) : &mproc[who_p];
		r = ESRCH; /* Default to error if target not found */
		if(target_mp)
			r = target_mp->mp_procgrp;
		break;
	}
	case PM_ISSETUGID:
		r = !!(rmp->mp_flags & TAINTED);
		break;

	default:
		r = EINVAL;
		break;
  }
  return(r);
}

/*===========================================================================*
 *				do_set					     *
 *===========================================================================*/
int
do_set(void)
{
/* Handle PM_SETUID, PM_SETEUID, PM_SETGID, PM_SETGROUPS, PM_SETEGID, and
 * SETSID. These calls have in common that, if successful, they will be
 * forwarded to VFS as well.
 */
  register struct mproc *rmp = mp;
  message m;
  int r = OK;
  int ngroups_val;
  uid_t uid_val;
  gid_t gid_val;

  memset(&m, 0, sizeof(m));

  switch(call_nr) {
	case PM_SETUID:
		uid_val = (uid_t)m_in.m_lc_pm_setuid.uid;
		/* NetBSD specific semantics: setuid(geteuid()) may fail.
		 * Allowed if real UID matches new UID, or if effective UID is SUPER_USER. */
		if (rmp->mp_realuid != uid_val && rmp->mp_effuid != SUPER_USER)
			return(EPERM);
		/* BSD semantics: always update all three fields. */
		rmp->mp_realuid = uid_val;
		rmp->mp_effuid = uid_val;
		rmp->mp_svuid = uid_val;

		m.m_type = VFS_PM_SETUID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effuid;
		m.VFS_PM_RID = rmp->mp_realuid;

		break;

	case PM_SETEUID:
		uid_val = (uid_t)m_in.m_lc_pm_setuid.uid;
		/* BSD semantics: seteuid(geteuid()) may fail.
		 * Allowed if real UID, saved UID, or effective UID is SUPER_USER matches new UID. */
		if (rmp->mp_realuid != uid_val && rmp->mp_svuid != uid_val &&
		    rmp->mp_effuid != SUPER_USER)
			return(EPERM);
		rmp->mp_effuid = uid_val;

		m.m_type = VFS_PM_SETUID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effuid;
		m.VFS_PM_RID = rmp->mp_realuid;

		break;

	case PM_SETGID:
		gid_val = (gid_t)m_in.m_lc_pm_setgid.gid;
		/* Allowed if real GID matches new GID, or if effective UID is SUPER_USER. */
		if (rmp->mp_realgid != gid_val && rmp->mp_effuid != SUPER_USER)
			return(EPERM);
		rmp->mp_realgid = gid_val;
		rmp->mp_effgid = gid_val;
		rmp->mp_svgid = gid_val;

		m.m_type = VFS_PM_SETGID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effgid;
		m.VFS_PM_RID = rmp->mp_realgid;

		break;

	case PM_SETEGID:
		gid_val = (gid_t)m_in.m_lc_pm_setgid.gid;
		/* Allowed if real GID, saved GID, or effective UID is SUPER_USER matches new GID. */
		if (rmp->mp_realgid != gid_val && rmp->mp_svgid != gid_val &&
		    rmp->mp_effuid != SUPER_USER)
			return(EPERM);
		rmp->mp_effgid = gid_val;

		m.m_type = VFS_PM_SETGID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_EID = rmp->mp_effgid;
		m.VFS_PM_RID = rmp->mp_realgid;

		break;

	case PM_SETGROUPS:
		if (rmp->mp_effuid != SUPER_USER)
			return(EPERM);

		ngroups_val = m_in.m_lc_pm_groups.num;

		if (ngroups_val > NGROUPS_MAX || ngroups_val < 0)
			return(EINVAL);

		if (ngroups_val > 0 && m_in.m_lc_pm_groups.ptr == 0)
			return(EFAULT);

		/* Copy supplemental groups from user space to PM. */
		r = sys_datacopy(who_e, (vir_bytes)m_in.m_lc_pm_groups.ptr, SELF,
			     (vir_bytes) rmp->mp_sgroups,
			     (phys_bytes)ngroups_val * sizeof(gid_t));
		if (r != OK)
			return(r);

		for (int i = 0; i < ngroups_val; i++) {
			if (rmp->mp_sgroups[i] > GID_MAX)
				return(EINVAL);
		}
		/* Clear any unused group slots. */
		for (int i = ngroups_val; i < NGROUPS_MAX; i++) {
			rmp->mp_sgroups[i] = 0;
		}
		rmp->mp_ngroups = ngroups_val;

		m.m_type = VFS_PM_SETGROUPS;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;
		m.VFS_PM_GROUP_NO = rmp->mp_ngroups;
		m.VFS_PM_GROUP_ADDR = (char *) rmp->mp_sgroups; /* Pointer in PM's address space */

		break;

	case PM_SETSID:
		/* A process cannot become a session leader if it's already
		 * a process group leader (e.g., has a child in its group). */
		if (rmp->mp_procgrp == rmp->mp_pid) return(EPERM);
		rmp->mp_procgrp = rmp->mp_pid;

		m.m_type = VFS_PM_SETSID;
		m.VFS_PM_ENDPT = rmp->mp_endpoint;

		break;

	default:
		return(EINVAL);
  }

  /* Send the request to VFS. */
  tell_vfs(rmp, &m);

  /* Do not reply until VFS has processed the request. */
  return(SUSPEND);
}