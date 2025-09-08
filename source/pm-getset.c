#include "pm.h"
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <limits.h>
#include <minix/com.h>
#include <signal.h>
#include "mproc.h"

int do_get(void) {
    struct mproc *rmp = mp;
    struct mproc *target;
    int r, ngroups;
    uid_t uid;
    gid_t gid;
    pid_t p;

    switch (call_nr) {
        case PM_GETGROUPS:
            ngroups = m_in.m_lc_pm_groups.num;
            if (ngroups > NGROUPS_MAX || ngroups < 0) return EINVAL;
            if (ngroups == 0) return rmp->mp_ngroups;
            if (ngroups < rmp->mp_ngroups) return EINVAL;
            r = sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e,
                             m_in.m_lc_pm_groups.ptr, ngroups * sizeof(gid_t));
            return (r != OK) ? r : rmp->mp_ngroups;
        case PM_GETUID:
            rmp->mp_reply.m_pm_lc_getuid.euid = rmp->mp_effuid;
            return rmp->mp_realuid;
        case PM_GETGID:
            rmp->mp_reply.m_pm_lc_getgid.egid = rmp->mp_effgid;
            return rmp->mp_realgid;
        case PM_GETPID:
            rmp->mp_reply.m_pm_lc_getpid.parent_pid = mproc[rmp->mp_parent].mp_pid;
            return mproc[who_p].mp_pid;
        case PM_GETPGRP:
            return rmp->mp_procgrp;
        case PM_GETSID:
            p = m_in.m_lc_pm_getsid.pid;
            target = p ? find_proc(p) : &mproc[who_p];
            return target ? target->mp_procgrp : ESRCH;
        case PM_ISSETUGID:
            return !!(rmp->mp_flags & TAINTED);
        default:
            return EINVAL;
    }
}

int do_set(void) {
    struct mproc *rmp = mp;
    message m;
    int r, ngroups, i;
    uid_t uid;
    gid_t gid;

    memset(&m, 0, sizeof(m));

    switch (call_nr) {
        case PM_SETUID:
            uid = m_in.m_lc_pm_setuid.uid;
            if (rmp->mp_realuid != uid && rmp->mp_effuid != SUPER_USER)
                return EPERM;
            rmp->mp_realuid = rmp->mp_effuid = rmp->mp_svuid = uid;
            m.m_type = VFS_PM_SETUID;
            break;
        case PM_SETEUID:
            uid = m_in.m_lc_pm_setuid.uid;
            if (rmp->mp_realuid != uid && rmp->mp_svuid != uid &&
                rmp->mp_effuid != SUPER_USER)
                return EPERM;
            rmp->mp_effuid = uid;
            m.m_type = VFS_PM_SETUID;
            break;
        case PM_SETGID:
            gid = m_in.m_lc_pm_setgid.gid;
            if (rmp->mp_realgid != gid && rmp->mp_effuid != SUPER_USER)
                return EPERM;
            rmp->mp_realgid = rmp->mp_effgid = rmp->mp_svgid = gid;
            m.m_type = VFS_PM_SETGID;
            break;
        case PM_SETEGID:
            gid = m_in.m_lc_pm_setgid.gid;
            if (rmp->mp_realgid != gid && rmp->mp_svgid != gid &&
                rmp->mp_effuid != SUPER_USER)
                return EPERM;
            rmp->mp_effgid = gid;
            m.m_type = VFS_PM_SETGID;
            break;
        case PM_SETGROUPS:
            if (rmp->mp_effuid != SUPER_USER)
                return EPERM;
            ngroups = m_in.m_lc_pm_groups.num;
            if (ngroups > NGROUPS_MAX || ngroups < 0 || (ngroups > 0 && m_in.m_lc_pm_groups.ptr == 0))
                return EINVAL;
            r = sys_datacopy(who_e, m_in.m_lc_pm_groups.ptr, SELF,
                             (vir_bytes)rmp->mp_sgroups, ngroups * sizeof(gid_t));
            if (r != OK)
                return r;
            for (i = 0; i < ngroups; i++) {
                if (rmp->mp_sgroups[i] > GID_MAX)
                    return EINVAL;
            }
            for (i = ngroups; i < NGROUPS_MAX; i++) {
                rmp->mp_sgroups[i] = 0;
            }
            rmp->mp_ngroups = ngroups;
            m.m_type = VFS_PM_SETGROUPS;
            break;
        case PM_SETSID:
            if (rmp->mp_procgrp == rmp->mp_pid) return EPERM;
            rmp->mp_procgrp = rmp->mp_pid;
            m.m_type = VFS_PM_SETSID;
            break;
        default:
            return EINVAL;
    }
    m.VFS_PM_ENDPT = rmp->mp_endpoint;
    m.VFS_PM_EID = rmp->mp_effuid;
    m.VFS_PM_RID = rmp->mp_realuid;

    tell_vfs(rmp, &m);

    return SUSPEND;
}