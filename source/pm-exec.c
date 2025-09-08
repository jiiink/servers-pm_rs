#include "pm.h"
#include <sys/stat.h>
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <minix/com.h>
#include <minix/vm.h>
#include <signal.h>
#include <libexec.h>
#include <sys/ptrace.h>
#include "mproc.h"

/*===========================================================================*
 *				do_exec					     *
 *===========================================================================*/
int do_exec(void)
{
	message m;

	memset(&m, 0, sizeof(m));
	m.m_type = VFS_PM_EXEC;
	m.VFS_PM_ENDPT = mp->mp_endpoint;
	m.VFS_PM_PATH = (void *) m_in.m_lc_pm_exec.name;
	m.VFS_PM_PATH_LEN = m_in.m_lc_pm_exec.namelen;
	m.VFS_PM_FRAME = (void *) m_in.m_lc_pm_exec.frame;
	m.VFS_PM_FRAME_LEN = m_in.m_lc_pm_exec.framelen;
	m.VFS_PM_PS_STR = m_in.m_lc_pm_exec.ps_str;

	tell_vfs(mp, &m);

	return SUSPEND;
}

/*===========================================================================*
 *				do_newexec				     *
 *===========================================================================*/
int do_newexec(void)
{
	int endpt, slot;
	vir_bytes src_ptr;
	struct mproc *rmp;
	struct exec_info args;
	int r;

	if (who_e != VFS_PROC_NR && who_e != RS_PROC_NR) return EPERM;

	endpt = m_in.m_lexec_pm_exec_new.endpt;
	if (pm_isokendpt(endpt, &slot) != OK) {
		panic("do_newexec: bad endpoint: %d", endpt);
	}
	rmp = &mproc[slot];

	src_ptr = m_in.m_lexec_pm_exec_new.ptr;
	r = sys_datacopy(who_e, src_ptr, SELF, (vir_bytes) &args, sizeof(args));
	if (r != OK) panic("do_newexec: sys_datacopy failed: %d", r);

	rmp->mp_flags &= ~TAINTED;

	const int suid_applied = (rmp->mp_tracer == NO_TRACER) && args.allow_setuid;

	if (suid_applied) {
		rmp->mp_effuid = args.new_uid;
		rmp->mp_effgid = args.new_gid;
	}

	rmp->mp_svuid = rmp->mp_effuid;
	rmp->mp_svgid = rmp->mp_effgid;

	if (suid_applied ||
	    rmp->mp_effuid != rmp->mp_realuid ||
	    rmp->mp_effgid != rmp->mp_realgid) {
		rmp->mp_flags |= TAINTED;
	}

	strncpy(rmp->mp_name, args.progname, PROC_NAME_LEN - 1);
	rmp->mp_name[PROC_NAME_LEN - 1] = '\0';

	rmp->mp_frame_addr = (vir_bytes) args.stack_high - args.frame_len;
	rmp->mp_frame_len = args.frame_len;

	rmp->mp_flags |= PARTIAL_EXEC;

	mp->mp_reply.m_pm_lexec_exec_new.suid = suid_applied;

	return OK;
}

/*===========================================================================*
 *				do_execrestart				     *
 *===========================================================================*/
int do_execrestart(void)
{
	int endpt, slot, result;
	struct mproc *rmp;
	vir_bytes pc, ps_str;

	if (who_e != RS_PROC_NR) return EPERM;

	endpt = m_in.m_rs_pm_exec_restart.endpt;
	if (pm_isokendpt(endpt, &slot) != OK) {
		panic("do_execrestart: bad endpoint: %d", endpt);
	}
	rmp = &mproc[slot];
	result = m_in.m_rs_pm_exec_restart.result;
	pc = m_in.m_rs_pm_exec_restart.pc;
	ps_str = m_in.m_rs_pm_exec_restart.ps_str;

	exec_restart(rmp, result, pc, rmp->mp_frame_addr, ps_str);

	return OK;
}

/*===========================================================================*
 *				exec_restart				     *
 *===========================================================================*/
void exec_restart(struct mproc *rmp, int result, vir_bytes pc, vir_bytes sp,
    vir_bytes ps_str)
{
	int r, sn;

	if (result != OK) {
		if (rmp->mp_flags & PARTIAL_EXEC) {
			sys_kill(rmp->mp_endpoint, SIGKILL);
			return;
		}
		reply((int)(rmp - mproc), result);
		return;
	}

	rmp->mp_flags &= ~PARTIAL_EXEC;

	for (sn = 1; sn < _NSIG; sn++) {
		if (sigismember(&rmp->mp_catch, sn)) {
			sigdelset(&rmp->mp_catch, sn);
			rmp->mp_sigact[sn].sa_handler = SIG_DFL;
			sigemptyset(&rmp->mp_sigact[sn].sa_mask);
		}
	}

	if (rmp->mp_tracer != NO_TRACER && !(rmp->mp_trace_flags & TO_NOEXEC)) {
		sn = (rmp->mp_trace_flags & TO_ALTEXEC) ? SIGSTOP : SIGTRAP;
		check_sig(rmp->mp_pid, sn, FALSE);
	}

	r = sys_exec(rmp->mp_endpoint, sp, (vir_bytes) rmp->mp_name, pc, ps_str);
	if (r != OK) panic("sys_exec failed: %d", r);
}