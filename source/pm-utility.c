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

pid_t get_free_pid(void)
{
  static pid_t next_pid = INIT_PID + 1;
  pid_t candidate;
  struct mproc *rmp;
  int in_use;

  for (;;) {
    candidate = (next_pid < NR_PIDS) ? (next_pid + 1) : (INIT_PID + 1);
    next_pid = candidate;
    in_use = 0;
    for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
      if (rmp->mp_pid == candidate || rmp->mp_procgrp == candidate) {
        in_use = 1;
        break;
      }
    }
    if (!in_use) return candidate;
  }
}

char *find_param(const char *name)
{
  const char *namep;
  char *envp;
  char *p;

  if (!name) return NULL;

  envp = (char *) monitor_params;
  while (*envp != 0) {
    namep = name;
    p = envp;
    while (*namep != 0 && *namep == *p) {
      namep++;
      p++;
    }
    if (*namep == '\0' && *p == '=') return p + 1;
    while (*envp++ != 0) { }
  }
  return NULL;
}

struct mproc *find_proc(pid_t lpid)
{
  struct mproc *rmp;

  for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
    if ((rmp->mp_flags & IN_USE) && rmp->mp_pid == lpid) return rmp;
  }
  return NULL;
}

int nice_to_priority(int nice, unsigned* new_q)
{
  unsigned range;
  unsigned denom;
  unsigned offset;
  unsigned calculated;

  if (!new_q) return EINVAL;
  if (nice < PRIO_MIN || nice > PRIO_MAX) return EINVAL;

  range = (unsigned)(MIN_USER_Q - MAX_USER_Q + 1);
  denom = (unsigned)(PRIO_MAX - PRIO_MIN + 1);
  offset = (unsigned)(nice - PRIO_MIN);
  calculated = MAX_USER_Q + (offset * range) / denom;

  if ((int)calculated < MAX_USER_Q) calculated = MAX_USER_Q;
  if (calculated > MIN_USER_Q) calculated = MIN_USER_Q;

  *new_q = calculated;
  return OK;
}

int pm_isokendpt(int endpoint, int *proc)
{
  int p;

  if (!proc) return EINVAL;

  p = _ENDPOINT_P(endpoint);
  *proc = p;
  if (p < 0 || p >= NR_PROCS) return EINVAL;
  if (endpoint != mproc[p].mp_endpoint) return EDEADEPT;
  if (!(mproc[p].mp_flags & IN_USE)) return EDEADEPT;
  return OK;
}

void tell_vfs(struct mproc *rmp, message *m_ptr)
{
  int r;

  if (rmp == NULL || m_ptr == NULL) panic("tell_vfs: bad args");
  if (rmp->mp_flags & (VFS_CALL | EVENT_CALL))
    panic("tell_vfs: not idle: %d", m_ptr->m_type);

  r = asynsend3(VFS_PROC_NR, m_ptr, AMF_NOREPLY);
  if (r != OK)
    panic("unable to send to VFS: %d", r);

  rmp->mp_flags |= VFS_CALL;
}

void set_rusage_times(struct rusage *r_usage, clock_t user_time, clock_t sys_time)
{
  u64_t usec;

  if (!r_usage) return;

  usec = ((u64_t)user_time * 1000000ULL) / (u64_t)sys_hz();
  r_usage->ru_utime.tv_sec = (time_t)(usec / 1000000ULL);
  r_usage->ru_utime.tv_usec = (suseconds_t)(usec % 1000000ULL);

  usec = ((u64_t)sys_time * 1000000ULL) / (u64_t)sys_hz();
  r_usage->ru_stime.tv_sec = (time_t)(usec / 1000000ULL);
  r_usage->ru_stime.tv_usec = (suseconds_t)(usec % 1000000ULL);
}