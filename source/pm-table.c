#define _TABLE

#include "pm.h"
#include <minix/callnr.h>
#include <signal.h>
#include "mproc.h"

typedef int (*sys_call_func)(void);

sys_call_func get_sys_call_func(int call_nr) {
    switch (call_nr) {
        case PM_EXIT: return do_exit;
        case PM_FORK: return do_fork;
        case PM_WAIT4: return do_wait4;
        case PM_GETPID: return do_get;
        case PM_SETUID: return do_set;
        case PM_GETUID: return do_get;
        case PM_STIME: return do_stime;
        case PM_PTRACE: return do_trace;
        case PM_SETGROUPS: return do_set;
        case PM_GETGROUPS: return do_get;
        case PM_KILL: return do_kill;
        case PM_SETGID: return do_set;
        case PM_GETGID: return do_get;
        case PM_EXEC: return do_exec;
        case PM_SETSID: return do_set;
        case PM_GETPGRP: return do_get;
        case PM_ITIMER: return do_itimer;
        case PM_GETMCONTEXT: return do_getmcontext;
        case PM_SETMCONTEXT: return do_setmcontext;
        case PM_SIGACTION: return do_sigaction;
        case PM_SIGSUSPEND: return do_sigsuspend;
        case PM_SIGPENDING: return do_sigpending;
        case PM_SIGPROCMASK: return do_sigprocmask;
        case PM_SIGRETURN: return do_sigreturn;
        case PM_SYSUNAME: return do_sysuname;
        case PM_GETPRIORITY: return do_getsetpriority;
        case PM_SETPRIORITY: return do_getsetpriority;
        case PM_GETTIMEOFDAY: return do_time;
        case PM_SETEUID: return do_set;
        case PM_SETEGID: return do_set;
        case PM_ISSETUGID: return do_get;
        case PM_GETSID: return do_get;
        case PM_CLOCK_GETRES: return do_getres;
        case PM_CLOCK_GETTIME: return do_gettime;
        case PM_CLOCK_SETTIME: return do_settime;
        case PM_GETRUSAGE: return do_getrusage;
        case PM_REBOOT: return do_reboot;
        case PM_SVRCTL: return do_svrctl;
        case PM_SPROF: return do_sprofile;
        case PM_PROCEVENTMASK: return do_proceventmask;
        case PM_SRV_FORK: return do_srv_fork;
        case PM_SRV_KILL: return do_srv_kill;
        case PM_EXEC_NEW: return do_newexec;
        case PM_EXEC_RESTART: return do_execrestart;
        case PM_GETEPINFO: return do_getepinfo;
        case PM_GETPROCNR: return do_getprocnr;
        case PM_GETSYSINFO: return do_getsysinfo;
        default: return NULL;
    }
}

sys_call_func get_call_vector(int index) {
    if (index < 0 || index >= NR_PM_CALLS) return NULL;
    return get_sys_call_func(index + PM_BASE);
}