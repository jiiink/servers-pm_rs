#include "pm.h"
#include <minix/callnr.h>
#include <minix/com.h>
#include <minix/ds.h>
#include <minix/endpoint.h>
#include <minix/minlib.h>
#include <minix/type.h>
#include <minix/vm.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <machine/archtypes.h>
#include "mproc.h"

#include "kernel/const.h"
#include "kernel/config.h"
#include "kernel/proc.h"

#if ENABLE_SYSCALL_STATS
EXTERN unsigned long calls_stats[NR_PM_CALLS];
#endif

static int get_nice_value(int queue);
static void handle_vfs_reply(void);

static void sef_local_startup(void);
static int sef_cb_init_fresh(int type, sef_init_info_t *info);

int main(void) {
  unsigned int call_index;
  int ipc_status, result;

  sef_local_startup();

  while (TRUE) {
    if (sef_receive_status(ANY, &m_in, &ipc_status) != OK)
      panic("PM sef_receive_status error");

    if (is_ipc_notify(ipc_status)) {
      if (_ENDPOINT_P(m_in.m_source) == CLOCK)
        expire_timers(m_in.m_notify.timestamp);
      continue;
    }

    who_e = m_in.m_source;
    if (pm_isokendpt(who_e, &who_p) != OK)
      panic("PM got message from invalid endpoint: %d", who_e);
    mp = &mproc[who_p];
    call_nr = m_in.m_type;

    if (mp->mp_flags & EXITING)
      continue;

    if (IS_VFS_PM_RS(call_nr) && who_e == VFS_PROC_NR) {
      handle_vfs_reply();
      result = SUSPEND;
    } else if (call_nr == PROC_EVENT_REPLY) {
      result = do_proc_event_reply();
    } else if (IS_PM_CALL(call_nr)) {
      call_index = (unsigned int)(call_nr - PM_BASE);
      if (call_index < NR_PM_CALLS && call_vec[call_index] != NULL) {
#if ENABLE_SYSCALL_STATS
        calls_stats[call_index]++;
#endif
        result = (*call_vec[call_index])();
      } else
        result = ENOSYS;
    } else
      result = ENOSYS;

    if (result != SUSPEND) reply(who_p, result);
  }
  return OK;
}

static void sef_local_startup(void) {
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);
  sef_setcb_signal_manager(process_ksig);
  sef_startup();
}

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info)) {
  int s;
  static struct boot_image image[NR_BOOT_PROCS];
  static char core_sigs[] = {SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGEMT, SIGFPE, SIGBUS, SIGSEGV};
  static char ign_sigs[] = {SIGCHLD, SIGWINCH, SIGCONT, SIGINFO};
  static char noign_sigs[] = {SIGILL, SIGTRAP, SIGEMT, SIGFPE, SIGBUS, SIGSEGV};
  message mess;

  for (struct mproc *rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++) {
    init_timer(&rmp->mp_timer);
    rmp->mp_magic = MP_MAGIC;
    rmp->mp_sigact = mpsigact[rmp - mproc];
    rmp->mp_eventsub = NO_EVENTSUB;
  }

  sigemptyset(&core_sset);
  for (char *sig_ptr = core_sigs; sig_ptr < core_sigs + sizeof(core_sigs); sig_ptr++)
    sigaddset(&core_sset, *sig_ptr);
  sigemptyset(&ign_sset);
  for (char *sig_ptr = ign_sigs; sig_ptr < ign_sigs + sizeof(ign_sigs); sig_ptr++)
    sigaddset(&ign_sset, *sig_ptr);
  sigemptyset(&noign_sset);
  for (char *sig_ptr = noign_sigs; sig_ptr < noign_sigs + sizeof(noign_sigs); sig_ptr++)
    sigaddset(&noign_sset, *sig_ptr);

  if ((s = sys_getmonparams(monitor_params, sizeof(monitor_params))) != OK)
    panic("get monitor params failed: %d", s);

  if ((s = sys_getimage(image)) != OK)
    panic("couldn't get image table: %d", s);

  procs_in_use = 0;
  for (struct boot_image *ip = &image[0]; ip < &image[NR_BOOT_PROCS]; ip++) {
    if (ip->proc_nr >= 0) {
      procs_in_use += 1;
      struct mproc *rmp = &mproc[ip->proc_nr];
      strlcpy(rmp->mp_name, ip->proc_name, PROC_NAME_LEN);
      sigemptyset(&rmp->mp_ignore);
      sigemptyset(&rmp->mp_sigmask);
      sigemptyset(&rmp->mp_catch);
      if (ip->proc_nr == INIT_PROC_NR) {
        rmp->mp_parent = INIT_PROC_NR;
        rmp->mp_procgrp = rmp->mp_pid = INIT_PID;
        rmp->mp_flags |= IN_USE;
        rmp->mp_scheduler = KERNEL;
        rmp->mp_nice = get_nice_value(USR_Q);
      } else {
        rmp->mp_parent = (ip->proc_nr == RS_PROC_NR) ? INIT_PROC_NR : RS_PROC_NR;
        rmp->mp_pid = get_free_pid();
        rmp->mp_flags |= IN_USE | PRIV_PROC;
        rmp->mp_scheduler = NONE;
        rmp->mp_nice = get_nice_value(SRV_Q);
      }
      rmp->mp_endpoint = ip->endpoint;

      memset(&mess, 0, sizeof(mess));
      mess.m_type = VFS_PM_INIT;
      mess.VFS_PM_SLOT = ip->proc_nr;
      mess.VFS_PM_PID = rmp->mp_pid;
      mess.VFS_PM_ENDPT = rmp->mp_endpoint;

      if ((s = ipc_send(VFS_PROC_NR, &mess)) != OK)
        panic("can't sync up with VFS: %d", s);
    }
  }

  memset(&mess, 0, sizeof(mess));
  mess.m_type = VFS_PM_INIT;
  mess.VFS_PM_ENDPT = NONE;
  if (ipc_sendrec(VFS_PROC_NR, &mess) != OK || mess.m_type != OK)
    panic("can't sync up with VFS");

  system_hz = sys_hz();
  sched_init();

  return OK;
}

void reply(int proc_nr, int result) {
  if (proc_nr < 0 || proc_nr >= NR_PROCS)
    panic("reply arg out of range: %d", proc_nr);

  struct mproc *rmp = &mproc[proc_nr];
  rmp->mp_reply.m_type = result;

  if (ipc_sendnb(rmp->mp_endpoint, &rmp->mp_reply) != OK)
    printf("PM can't reply to %d (%s)\n", rmp->mp_endpoint, rmp->mp_name);
}

static int get_nice_value(int queue) {
  int nice_val = (queue - USER_Q) * (PRIO_MAX - PRIO_MIN + 1) / (MIN_USER_Q - MAX_USER_Q + 1);
  if (nice_val > PRIO_MAX) nice_val = PRIO_MAX;
  if (nice_val < PRIO_MIN) nice_val = PRIO_MIN;
  return nice_val;
}

static void handle_vfs_reply(void) {
  endpoint_t proc_e;
  int proc_n, new_parent;

  if (call_nr == VFS_PM_REBOOT_REPLY) {
    sys_abort(abort_flag);
    return;
  }

  proc_e = m_in.VFS_PM_ENDPT;
  if (pm_isokendpt(proc_e, &proc_n) != OK) {
    panic("handle_vfs_reply: got bad endpoint from VFS: %d", proc_e);
  }

  struct mproc *rmp = &mproc[proc_n];
  if (!(rmp->mp_flags & VFS_CALL))
    panic("handle_vfs_reply: reply without request: %d", call_nr);

  new_parent = rmp->mp_flags & NEW_PARENT;
  rmp->mp_flags &= ~(VFS_CALL | NEW_PARENT);

  if (rmp->mp_flags & UNPAUSED)
    panic("handle_vfs_reply: UNPAUSED set on entry: %d", call_nr);

  switch (call_nr) {
    case VFS_PM_SETUID_REPLY:
    case VFS_PM_SETGID_REPLY:
    case VFS_PM_SETGROUPS_REPLY:
      reply(rmp - mproc, OK);
      break;
    case VFS_PM_SETSID_REPLY:
      reply(rmp - mproc, rmp->mp_procgrp);
      break;
    case VFS_PM_EXEC_REPLY:
      exec_restart(rmp, m_in.VFS_PM_STATUS, (vir_bytes)m_in.VFS_PM_PC,
                   (vir_bytes)m_in.VFS_PM_NEWSP, (vir_bytes)m_in.VFS_PM_NEWPS_STR);
      break;
    case VFS_PM_CORE_REPLY:
      if (m_in.VFS_PM_STATUS == OK)
        rmp->mp_sigstatus |= WCOREFLAG;
    case VFS_PM_EXIT_REPLY:
      assert(rmp->mp_flags & EXITING);
      publish_event(rmp);
      return;
    case VFS_PM_FORK_REPLY:
      if (rmp->mp_scheduler != KERNEL && rmp->mp_scheduler != NONE) {
        if (sched_start_user(rmp->mp_scheduler, rmp) != OK) {
          rmp->mp_scheduler = NONE;
          exit_proc(rmp, -1, FALSE);
          if (!new_parent)
            reply(rmp->mp_parent, -1);
        } else {
          reply(proc_n, OK);
          if (!new_parent)
            reply(rmp->mp_parent, rmp->mp_pid);
        }
      }
      break;
    case VFS_PM_SRV_FORK_REPLY:
      break;
    case VFS_PM_UNPAUSE_REPLY:
      assert(rmp->mp_flags & PROC_STOPPED);
      rmp->mp_flags |= UNPAUSED;
      publish_event(rmp);
      return;
    default:
      panic("handle_vfs_reply: unknown reply code: %d", call_nr);
  }

  if ((rmp->mp_flags & (IN_USE | EXITING)) == IN_USE)
    restart_sigs(rmp);
}