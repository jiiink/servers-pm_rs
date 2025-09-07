/* This file handles the EXEC system call. */

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

#define ESCRIPT	(-2000)	/* Returned by read_header for a #! script. */
#define PTRSIZE	sizeof(char *) /* Size of pointers in argv[] and envp[]. */

/* Function prototypes */
static int validate_exec_params(void);
static void prepare_exec_message(message *m);
static void handle_exec_result(struct mproc *rmp, int result, 
                               vir_bytes pc, vir_bytes sp, vir_bytes ps_str);

/*===========================================================================*
 *				validate_exec_params			     *
 *===========================================================================*/
static int validate_exec_params(void)
{
	/* Basic parameter validation */
	if (m_in.m_lc_pm_exec.namelen <= 0 || 
	    m_in.m_lc_pm_exec.framelen < 0) {
		return EINVAL;
	}
	return OK;
}

/*===========================================================================*
 *				prepare_exec_message			     *
 *===========================================================================*/
static void prepare_exec_message(message *m)
{
	if (m == NULL) {
		return;
	}

	memset(m, 0, sizeof(*m));
	m->m_type = VFS_PM_EXEC;
	m->VFS_PM_ENDPT = mp->mp_endpoint;
	m->VFS_PM_PATH = (void *)m_in.m_lc_pm_exec.name;
	m->VFS_PM_PATH_LEN = m_in.m_lc_pm_exec.namelen;
	m->VFS_PM_FRAME = (void *)m_in.m_lc_pm_exec.frame;
	m->VFS_PM_FRAME_LEN = m_in.m_lc_pm_exec.framelen;
	m->VFS_PM_PS_STR = m_in.m_lc_pm_exec.ps_str;
}

/*===========================================================================*
 *				do_exec					     *
 *===========================================================================*/
int do_exec(void)
{
	message m;
	int r;

	/* Validate parameters */
	r = validate_exec_params();
	if (r != OK) {
		return r;
	}

	/* Forward call to VFS */
	prepare_exec_message(&m);
	tell_vfs(mp, &m);

	return SUSPEND;
}

/*===========================================================================*
 *				do_newexec				     *
 *===========================================================================*/
int do_newexec(void)
{
	int proc_e, proc_n, allow_setuid;
	vir_bytes ptr;
	struct mproc *rmp;
	struct exec_info args;
	int r;
	int i;

	/* Only VFS and RS can call this */
	if (who_e != VFS_PROC_NR && who_e != RS_PROC_NR) {
		return EPERM;
	}

	proc_e = m_in.m_lexec_pm_exec_new.endpt;
	if (pm_isokendpt(proc_e, &proc_n) != OK) {
		panic("do_newexec: got bad endpoint: %d", proc_e);
	}

	rmp = &mproc[proc_n];
	ptr = m_in.m_lexec_pm_exec_new.ptr;

	/* Copy exec info */
	r = sys_datacopy(who_e, ptr, SELF, (vir_bytes)&args, sizeof(args));
	if (r != OK) {
		panic("do_newexec: sys_datacopy failed: %d", r);
	}

	/* Initialize flags */
	allow_setuid = 0;
	rmp->mp_flags &= ~TAINTED;

	/* Check if setuid execution is allowed */
	if (rmp->mp_tracer == NO_TRACER) {
		allow_setuid = 1;
	}

	/* Update effective IDs if allowed */
	if (allow_setuid && args.allow_setuid) {
		rmp->mp_effuid = args.new_uid;
		rmp->mp_effgid = args.new_gid;
	}

	/* Always update saved IDs */
	rmp->mp_svuid = rmp->mp_effuid;
	rmp->mp_svgid = rmp->mp_effgid;

	/* Check if process should be marked as tainted */
	if (allow_setuid && args.allow_setuid) {
		rmp->mp_flags |= TAINTED;
	} else if (rmp->mp_effuid != rmp->mp_realuid ||
	           rmp->mp_effgid != rmp->mp_realgid) {
		rmp->mp_flags |= TAINTED;
	}

	/* Save program name */
	strncpy(rmp->mp_name, args.progname, PROC_NAME_LEN - 1);
	rmp->mp_name[PROC_NAME_LEN - 1] = '\0';

	/* Save stack frame info */
	rmp->mp_frame_addr = (vir_bytes)args.stack_high - args.frame_len;
	rmp->mp_frame_len = args.frame_len;

	/* Mark as partial exec */
	rmp->mp_flags |= PARTIAL_EXEC;

	/* Prepare reply */
	mp->mp_reply.m_pm_lexec_exec_new.suid = (allow_setuid && args.allow_setuid);

	return OK;
}

/*===========================================================================*
 *				do_execrestart				     *
 *===========================================================================*/
int do_execrestart(void)
{
	int proc_e, proc_n;
	struct mproc *rmp;
	int result;
	vir_bytes pc, ps_str;

	/* Only RS can call this */
	if (who_e != RS_PROC_NR) {
		return EPERM;
	}

	proc_e = m_in.m_rs_pm_exec_restart.endpt;
	if (pm_isokendpt(proc_e, &proc_n) != OK) {
		panic("do_execrestart: got bad endpoint: %d", proc_e);
	}

	rmp = &mproc[proc_n];
	result = m_in.m_rs_pm_exec_restart.result;
	pc = m_in.m_rs_pm_exec_restart.pc;
	ps_str = m_in.m_rs_pm_exec_restart.ps_str;

	exec_restart(rmp, result, pc, rmp->mp_frame_addr, ps_str);

	return OK;
}

/*===========================================================================*
 *				handle_exec_result			     *
 *===========================================================================*/
static void handle_exec_result(struct mproc *rmp, int result,
                               vir_bytes pc, vir_bytes sp, vir_bytes ps_str)
{
	int sn;
	int r;

	if (rmp == NULL) {
		return;
	}

	/* Handle failure */
	if (result != OK) {
		if (rmp->mp_flags & PARTIAL_EXEC) {
			sys_kill(rmp->mp_endpoint, SIGKILL);
			return;
		}
		reply(rmp - mproc, result);
		return;
	}

	/* Clear partial exec flag */
	rmp->mp_flags &= ~PARTIAL_EXEC;

	/* Reset caught signals */
	for (sn = 1; sn < _NSIG; sn++) {
		if (sigismember(&rmp->mp_catch, sn)) {
			sigdelset(&rmp->mp_catch, sn);
			rmp->mp_sigact[sn].sa_handler = SIG_DFL;
			sigemptyset(&rmp->mp_sigact[sn].sa_mask);
		}
	}

	/* Handle tracing */
	if (rmp->mp_tracer != NO_TRACER && !(rmp->mp_trace_flags & TO_NOEXEC)) {
		sn = (rmp->mp_trace_flags & TO_ALTEXEC) ? SIGSTOP : SIGTRAP;
		check_sig(rmp->mp_pid, sn, FALSE);
	}

	/* Execute with new SP and PC */
	r = sys_exec(rmp->mp_endpoint, sp, (vir_bytes)rmp->mp_name, pc, ps_str);
	if (r != OK) {
		panic("sys_exec failed: %d", r);
	}
}

/*===========================================================================*
 *				exec_restart				     *
 *===========================================================================*/
void exec_restart(struct mproc *rmp, int result, vir_bytes pc, 
                  vir_bytes sp, vir_bytes ps_str)
{
	handle_exec_result(rmp, result, pc, sp, ps_str);
}