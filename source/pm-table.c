/* This file contains the table used to map system call numbers onto the
 * routines that perform them.
 */

#define _TABLE

#include "pm.h"
#include <minix/callnr.h>
#include "mproc.h"

typedef int (*pm_call_t)(void);

#define IDX(n) ((int)((n) - PM_BASE))
#define STATIC_ASSERT(cond, name) typedef char static_assert_##name[(cond) ? 1 : -1]

STATIC_ASSERT(IDX(PM_EXIT) >= 0, pm_exit_index_nonnegative);
STATIC_ASSERT(IDX(PM_GETSYSINFO) < NR_PM_CALLS, pm_getsysinfo_index_in_range);

const pm_call_t call_vec[NR_PM_CALLS] = {
	[IDX(PM_EXIT)]		= do_exit,		/* _exit(2) */
	[IDX(PM_FORK)]		= do_fork,		/* fork(2) */
	[IDX(PM_WAIT4)]		= do_wait4,		/* wait4(2) */
	[IDX(PM_GETPID)]	= do_get,		/* get[p]pid(2) */
	[IDX(PM_SETUID)]	= do_set,		/* setuid(2) */
	[IDX(PM_GETUID)]	= do_get,		/* get[e]uid(2) */
	[IDX(PM_STIME)]		= do_stime,		/* stime(2) */
	[IDX(PM_PTRACE)]	= do_trace,		/* ptrace(2) */
	[IDX(PM_SETGROUPS)]	= do_set,		/* setgroups(2) */
	[IDX(PM_GETGROUPS)]	= do_get,		/* getgroups(2) */
	[IDX(PM_KILL)]		= do_kill,		/* kill(2) */
	[IDX(PM_SETGID)]	= do_set,		/* setgid(2) */
	[IDX(PM_GETGID)]	= do_get,		/* get[e]gid(2) */
	[IDX(PM_EXEC)]		= do_exec,		/* execve(2) */
	[IDX(PM_SETSID)]	= do_set,		/* setsid(2) */
	[IDX(PM_GETPGRP)]	= do_get,		/* getpgrp(2) */
	[IDX(PM_ITIMER)]	= do_itimer,		/* [gs]etitimer(2) */
	[IDX(PM_GETMCONTEXT)]	= do_getmcontext,	/* getmcontext(2) */
	[IDX(PM_SETMCONTEXT)]	= do_setmcontext,	/* setmcontext(2) */
	[IDX(PM_SIGACTION)]	= do_sigaction,		/* sigaction(2) */
	[IDX(PM_SIGSUSPEND)]	= do_sigsuspend,	/* sigsuspend(2) */
	[IDX(PM_SIGPENDING)]	= do_sigpending,	/* sigpending(2) */
	[IDX(PM_SIGPROCMASK)]	= do_sigprocmask,	/* sigprocmask(2) */
	[IDX(PM_SIGRETURN)]	= do_sigreturn,		/* sigreturn(2) */
	[IDX(PM_SYSUNAME)]	= do_sysuname,		/* sysuname(2) */
	[IDX(PM_GETPRIORITY)]	= do_getsetpriority,	/* getpriority(2) */
	[IDX(PM_SETPRIORITY)]	= do_getsetpriority,	/* setpriority(2) */
	[IDX(PM_GETTIMEOFDAY)]	= do_time,		/* gettimeofday(2) */
	[IDX(PM_SETEUID)]	= do_set,		/* geteuid(2) */
	[IDX(PM_SETEGID)]	= do_set,		/* setegid(2) */
	[IDX(PM_ISSETUGID)]	= do_get,		/* issetugid */
	[IDX(PM_GETSID)]	= do_get,		/* getsid(2) */
	[IDX(PM_CLOCK_GETRES)]	= do_getres,		/* clock_getres(2) */
	[IDX(PM_CLOCK_GETTIME)]	= do_gettime,		/* clock_gettime(2) */
	[IDX(PM_CLOCK_SETTIME)]	= do_settime,		/* clock_settime(2) */
	[IDX(PM_GETRUSAGE)]	= do_getrusage,		/* getrusage(2) */
	[IDX(PM_REBOOT)]	= do_reboot,		/* reboot(2) */
	[IDX(PM_SVRCTL)]	= do_svrctl,		/* svrctl(2) */
	[IDX(PM_SPROF)]		= do_sprofile,		/* sprofile(2) */
	[IDX(PM_PROCEVENTMASK)]	= do_proceventmask,	/* proceventmask(2) */
	[IDX(PM_SRV_FORK)]	= do_srv_fork,		/* srv_fork(2) */
	[IDX(PM_SRV_KILL)]	= do_srv_kill,		/* srv_kill(2) */
	[IDX(PM_EXEC_NEW)]	= do_newexec,
	[IDX(PM_EXEC_RESTART)]	= do_execrestart,
	[IDX(PM_GETEPINFO)]	= do_getepinfo,		/* getepinfo(2) */
	[IDX(PM_GETPROCNR)]	= do_getprocnr,		/* getprocnr(2) */
	[IDX(PM_GETSYSINFO)]	= do_getsysinfo,	/* getsysinfo(2) */
};