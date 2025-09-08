#include "pm.h"
#include <sys/resource.h>
#include <sys/stat.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/endpoint.h>
#include <fcntl.h>
#include <signal.h>
#include "mproc.h"
#include <minix/config.h>
#include <minix/timers.h>
#include <machine/archtypes.h>
#include "kernel/const.h"
#include "kernel/config.h"
#include "kernel/type.h"
#include "kernel/proc.h"

pid_t get_free_pid() {
    static pid_t next_pid = INIT_PID + 1;
    struct mproc *rmp;

    while (1) {
        next_pid = (next_pid < NR_PIDS) ? next_pid + 1 : INIT_PID + 1;
        int pid_free = 1;
        for (rmp = mproc; rmp < mproc + NR_PROCS; rmp++) {
            if (rmp->mp_pid == next_pid || rmp->mp_procgrp == next_pid) {
                pid_free = 0;
                break;
            }
        }
        if (pid_free) {
            return next_pid;
        }
    }
}

char *find_param(const char *name) {
    const char *namep;
    char *envp = (char *)monitor_params;

    while (*envp != '\0') {
        namep = name;
        while (*namep != '\0' && *namep == *envp) {
            namep++;
            envp++;
        }
        if (*namep == '\0' && *envp == '=') {
            return envp + 1;
        }
        while (*envp++ != '\0');
    }
    return NULL;
}

struct mproc *find_proc(pid_t lpid) {
    struct mproc *rmp;

    for (rmp = mproc; rmp < mproc + NR_PROCS; rmp++) {
        if ((rmp->mp_flags & IN_USE) && (rmp->mp_pid == lpid)) {
            return rmp;
        }
    }
    return NULL;
}

int nice_to_priority(int nice, unsigned* new_q) {
    if (nice < PRIO_MIN || nice > PRIO_MAX) return EINVAL;

    *new_q = MAX_USER_Q + (nice - PRIO_MIN) * (MIN_USER_Q - MAX_USER_Q + 1) / (PRIO_MAX - PRIO_MIN + 1);

    if ((signed)*new_q < MAX_USER_Q) *new_q = MAX_USER_Q;
    if (*new_q > MIN_USER_Q) *new_q = MIN_USER_Q;

    return OK;
}

int pm_isokendpt(int endpoint, int *proc) {
    *proc = _ENDPOINT_P(endpoint);
    if (*proc < 0 || *proc >= NR_PROCS) return EINVAL;
    if (endpoint != mproc[*proc].mp_endpoint) return EDEADEPT;
    if (!(mproc[*proc].mp_flags & IN_USE)) return EDEADEPT;
    return OK;
}

void tell_vfs(struct mproc *rmp, message *m_ptr) {
    if (rmp->mp_flags & (VFS_CALL | EVENT_CALL)) {
        panic("tell_vfs: not idle: %d", m_ptr->m_type);
    }
    int r = asynsend3(VFS_PROC_NR, m_ptr, AMF_NOREPLY);
    if (r != OK) {
        panic("unable to send to VFS: %d", r);
    }
    rmp->mp_flags |= VFS_CALL;
}

void set_rusage_times(struct rusage *r_usage, clock_t user_time, clock_t sys_time) {
    u64_t usec = user_time * 1000000 / sys_hz();
    r_usage->ru_utime.tv_sec = usec / 1000000;
    r_usage->ru_utime.tv_usec = usec % 1000000;

    usec = sys_time * 1000000 / sys_hz();
    r_usage->ru_stime.tv_sec = usec / 1000000;
    r_usage->ru_stime.tv_usec = usec % 1000000;
}