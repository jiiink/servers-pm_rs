/* This file handles the EXEC system call.  It performs the work as follows:
 *    - see if the permissions allow the file to be executed
 *    - read the header and extract the sizes
 *    - fetch the initial args and environment from the user space
 *    - allocate the memory for the new process
 *    - copy the initial stack from PM to the process
 *    - read in the text and data segments and copy to the process
 *    - take care of setuid and setgid bits
 *    - fix up 'mproc' table
 *    - tell kernel about EXEC
 *    - save offset to initial argc (for procfs)
 *
 * The entry points into this file are:
 *   do_exec:	 perform the EXEC system call
 *   do_newexec: handle PM part of exec call after VFS
 *   do_execrestart: finish the special exec call for RS
 *   exec_restart: finish a regular exec call
 */

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
int
do_exec(void)
{
	message m;
	struct mproc *current_mp = mp;

	/* Forward call to VFS */
	memset(&m, 0, sizeof(m));
	m.m_type = VFS_PM_EXEC;
	m.VFS_PM_ENDPT = current_mp->mp_endpoint;
	m.VFS_PM_PATH = (void *)m_in.m_lc_pm_exec.name;
	m.VFS_PM_PATH_LEN = m_in.m_lc_pm_exec.namelen;
	m.VFS_PM_FRAME = (void *)m_in.m_lc_pm_exec.frame;
	m.VFS_PM_FRAME_LEN = m_in.m_lc_pm_exec.framelen;
	m.VFS_PM_PS_STR = m_in.m_lc_pm_exec.ps_str;

	tell_vfs(current_mp, &m);

	/* Do not reply; VFS will reply later via `handle_vfs_reply`. */
	return SUSPEND;
}


/*===========================================================================*
 *				do_newexec				     *
 *===========================================================================*/
int do_newexec(void)
{
	int proc_e_val, proc_n_val, allow_setuid_exec;
	vir_bytes exec_info_ptr;
	struct mproc *target_rmp;
	struct exec_info args;
	int r;

	/* Only VFS and RS are allowed to call do_newexec. */
	if (who_e != VFS_PROC_NR && who_e != RS_PROC_NR)
		return EPERM;

	proc_e_val= m_in.m_lexec_pm_exec_new.endpt;
	if (pm_isokendpt(proc_e_val, &proc_n_val) != OK) {
		panic("do_newexec: got bad endpoint: %d", proc_e_val);
	}
	target_rmp= &mproc[proc_n_val];
	exec_info_ptr= m_in.m_lexec_pm_exec_new.ptr;

	/* Copy exec_info structure from caller (VFS/RS) to PM's memory. */
	r= sys_datacopy(who_e, exec_info_ptr, SELF, (vir_bytes)&args, sizeof(args));
	if (r != OK) {
		panic("do_newexec: sys_datacopy for exec_info failed: %d", r);
	}

	allow_setuid_exec = 0;	/* By default, do not allow setuid execution */
	target_rmp->mp_flags &= ~TAINTED;	/* By default not tainted */

	/* Setuid execution is allowed only if the process is not traced. */
	if (target_rmp->mp_tracer == NO_TRACER) {
		allow_setuid_exec = 1;
	}

	/* Apply setuid/setgid if allowed and requested by the executable. */
	if (allow_setuid_exec && args.allow_setuid) {
		target_rmp->mp_effuid = args.new_uid;
		target_rmp->mp_effgid = args.new_gid;
	}

	/* Always update the saved user and group ID at this point. */
	target_rmp->mp_svuid = target_rmp->mp_effuid;
	target_rmp->mp_svgid = target_rmp->mp_effgid;

	/* A process is considered 'tainted' when it's executing with
	 * setuid or setgid bit set, or when the real{u,g}id doesn't
	 * match the eff{u,g}id, respectively. */
	if ((allow_setuid_exec && args.allow_setuid) ||
		(target_rmp->mp_effuid != target_rmp->mp_realuid ||
		 target_rmp->mp_effgid != target_rmp->mp_realgid)) {
		target_rmp->mp_flags |= TAINTED;
	}

	/* System will save command line for debugging, ps(1) output, etc. */
	(void)strncpy(target_rmp->mp_name, args.progname, sizeof(target_rmp->mp_name)-1);
	target_rmp->mp_name[sizeof(target_rmp->mp_name)-1] = '\0';

	/* Save offset to initial argc (for procfs) */
	target_rmp->mp_frame_addr = (vir_bytes) args.stack_high - args.frame_len;
	target_rmp->mp_frame_len = args.frame_len;

	/* Kill process if something goes wrong after this point. */
	target_rmp->mp_flags |= PARTIAL_EXEC;

	mp->mp_reply.m_pm_lexec_exec_new.suid = (allow_setuid_exec && args.allow_setuid);

	return r;
}

/*===========================================================================*
 *				do_execrestart				     *
 *===========================================================================*/
int do_execrestart(void)
{
	int proc_e_val, proc_n_val, result;
	struct mproc *target_rmp;
	vir_bytes pc_val, ps_str_val;

	/* Only RS is allowed to call do_execrestart. */
	if (who_e != RS_PROC_NR)
		return EPERM;

	proc_e_val = m_in.m_rs_pm_exec_restart.endpt;
	if (pm_isokendpt(proc_e_val, &proc_n_val) != OK) {
		panic("do_execrestart: got bad endpoint: %d", proc_e_val);
	}
	target_rmp = &mproc[proc_n_val];
	result = m_in.m_rs_pm_exec_restart.result;
	pc_val = m_in.m_rs_pm_exec_restart.pc;
	ps_str_val = m_in.m_rs_pm_exec_restart.ps_str;

	/* Resume the exec process with the provided execution context. */
	exec_restart(target_rmp, result, pc_val, target_rmp->mp_frame_addr, ps_str_val);

	return OK;
}

/*===========================================================================*
 *				exec_restart				     *
 *===========================================================================*/
void exec_restart(struct mproc *rmp, int result, vir_bytes pc, vir_bytes sp,
       vir_bytes ps_str)
{
	int r, sn;

	if (result != OK)
	{
		if (rmp->mp_flags & PARTIAL_EXEC)
		{
			/* Something went wrong during exec; kill the process. */
			sys_kill(rmp->mp_endpoint, SIGKILL);
			return;
		}
		/* If it wasn't a partial exec, reply with the error to the original caller. */
		reply((int)(rmp-mproc), result);
		return;
	}

	rmp->mp_flags &= ~PARTIAL_EXEC;

	/* Fix 'mproc' fields, tell kernel that exec is done, reset caught
	 * sigs. Clear any pending signals and reset signal actions to default.
	 */
	for (sn = 1; sn < _NSIG; sn++) {
		/* Clear pending, catch, ignore for this signal */
		sigdelset(&rmp->mp_sigpending, sn);
		sigdelset(&rmp->mp_ksigpending, sn);
		sigdelset(&rmp->mp_ignore, sn);

		/* Reset caught signals to default handling */
		if (sigismember(&rmp->mp_catch, sn)) {
			sigdelset(&rmp->mp_catch, sn);
			rmp->mp_sigact[sn].sa_handler = SIG_DFL;
			sigemptyset(&rmp->mp_sigact[sn].sa_mask);
		}
	}
	sigemptyset(&rmp->mp_sigmask); /* Clear signal mask */
	sigemptyset(&rmp->mp_sigtrace); /* Clear traced signals */


	/* Cause a signal if this process is traced.
	 * Do this before making the process runnable again!
	 */
	if (rmp->mp_tracer != NO_TRACER && !(rmp->mp_trace_flags & TO_NOEXEC))
	{
		sn = (rmp->mp_trace_flags & TO_ALTEXEC) ? SIGSTOP : SIGTRAP;
		/* `FALSE` for ksig here as this is an internal PM-initiated signal */
		check_sig(rmp->mp_pid, sn, FALSE /* ksig */);
	}

	/* Call kernel to exec with SP and PC set by VFS. */
	r = sys_exec(rmp->mp_endpoint, sp, (vir_bytes)rmp->mp_name, pc, ps_str);
	if (r != OK) {
		/* If sys_exec fails, it's a critical kernel error at this stage. */
		panic("sys_exec failed for endpoint %d: %d", rmp->mp_endpoint, r);
	}
}