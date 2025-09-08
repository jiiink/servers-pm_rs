/* This file contains some utility routines for RS.
 *
 * Changes:
 *   Nov 22, 2009: Created    (Cristiano Giuffrida)
 */

#include "inc.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <minix/sched.h>
#include "kernel/proc.h"

#define PRINT_SEP() printf("---------------------------------------------------------------------------------\n")

/*===========================================================================*
 *				 init_service				     *
 *===========================================================================*/
int init_service(struct rproc *rp, int type, int flags)
{
  int r, prepare_state;
  message m;
  endpoint_t old_endpoint;

  rp->r_flags |= RS_INITIALIZING;              /* now initializing */
  rp->r_alive_tm = getticks();
  rp->r_check_tm = rp->r_alive_tm + 1;         /* expect reply within period */

  if(rp->r_priv.s_flags & ROOT_SYS_PROC) {
      return OK;
  }

  old_endpoint = NONE;
  prepare_state = SEF_LU_STATE_NULL;
  if(rp->r_old_rp) {
      old_endpoint = rp->r_upd.state_endpoint;
      prepare_state = rp->r_upd.prepare_state;
  }
  else if(rp->r_prev_rp) {
      old_endpoint = rp->r_prev_rp->r_pub->endpoint;
  }

  if(rp->r_pub->sys_flags & SF_USE_SCRIPT) {
      flags |= SEF_INIT_SCRIPT_RESTART;
  }

  memset(&m, 0, sizeof(m));
  m.m_type = RS_INIT;
  m.m_rs_init.type = (short) type;
  m.m_rs_init.flags = flags;
  m.m_rs_init.rproctab_gid = rinit.rproctab_gid;
  m.m_rs_init.old_endpoint = old_endpoint;
  m.m_rs_init.restarts = (short) (rp->r_restarts + 1);
  m.m_rs_init.buff_addr = rp->r_map_prealloc_addr;
  m.m_rs_init.buff_len  = rp->r_map_prealloc_len;
  m.m_rs_init.prepare_state = prepare_state;
  rp->r_map_prealloc_addr = 0;
  rp->r_map_prealloc_len = 0;
  r = rs_asynsend(rp, &m, 0);

  return r;
}

/*===========================================================================*
 *				 fi_service				     *
 *===========================================================================*/
int fi_service(struct rproc *rp)
{
  message m;
  memset(&m, 0, sizeof(m));

  m.m_type = COMMON_REQ_FI_CTL;
  m.m_lsys_fi_ctl.subtype = RS_FI_CRASH;
  return rs_asynsend(rp, &m, 0);
}

/*===========================================================================*
 *			      fill_send_mask                                 *
 *===========================================================================*/
void fill_send_mask(sys_map_t *send_mask, int set_bits)
{
  int i;

  for (i = 0; i < NR_SYS_PROCS; i++) {
	if (set_bits)
		set_sys_bit(*send_mask, i);
	else
		unset_sys_bit(*send_mask, i);
  }
}

/*===========================================================================*
 *			      fill_call_mask                                 *
 *===========================================================================*/
void fill_call_mask(int *calls, int tot_nr_calls, bitchunk_t *call_mask,
    int call_base, int is_init)
{
  int i;
  int call_mask_size, nr_calls;

  call_mask_size = BITMAP_CHUNKS(tot_nr_calls);

  nr_calls = 0;
  for(i = 0; calls[i] != NULL_C; i++) {
      nr_calls++;
  }

  if(nr_calls == 1 && calls[0] == ALL_C) {
      for(i = 0; i < call_mask_size; i++) {
          call_mask[i] = (~(bitchunk_t)0);
      }
      if (call_mask_size > 0) {
          int bits_last = tot_nr_calls % BITCHUNK_BITS;
          if (bits_last != 0) {
              bitchunk_t mask = ((bitchunk_t)1 << bits_last) - 1;
              call_mask[call_mask_size - 1] &= mask;
          }
      }
  }
  else {
      if(is_init) {
          for(i = 0; i < call_mask_size; i++) {
              call_mask[i] = 0;
          }
      }
      for(i = 0; i < nr_calls; i++) {
          int bit = calls[i] - call_base;
          if (bit >= 0 && bit < tot_nr_calls) {
              SET_BIT(call_mask, bit);
          }
      }
  }
}

/*===========================================================================*
 *			     srv_to_string_gen				     *
 *===========================================================================*/
char* srv_to_string_gen(struct rproc *rp, int is_verbose)
{
  struct rprocpub *rpub;
  int slot_nr;
  char *srv_string;
#define max_len (RS_MAX_LABEL_LEN + 256)
  static char srv_string_pool[3][max_len];
  static int srv_string_pool_index = 0;

  rpub = rp->r_pub;
  slot_nr = rp - rproc;
  srv_string = srv_string_pool[srv_string_pool_index];
  srv_string_pool_index = (srv_string_pool_index + 1) % 3;

#define srv_str(cmd) ((cmd) == NULL || (cmd)[0] == '\0' ? "_" : (cmd))
#define srv_active_str(rp) ((rp)->r_flags & RS_ACTIVE ? "*" : " ")
#define srv_version_str(rp) ((rp)->r_new_rp || (rp)->r_next_rp ? "-" : \
    ((rp)->r_old_rp || (rp)->r_prev_rp ? "+" : " "))

  if(is_verbose) {
      snprintf(srv_string, max_len, "service '%s'%s%s"
		"(slot %d, ep %d, pid %d, cmd %s,"
		" script %s, proc %s, major %d,"
		" flags 0x%03x, sys_flags 0x%02x)",
		rpub->label, srv_active_str(rp), srv_version_str(rp),
		slot_nr, rpub->endpoint, rp->r_pid, srv_str(rp->r_cmd),
		srv_str(rp->r_script), srv_str(rpub->proc_name), rpub->dev_nr,
		rp->r_flags, rpub->sys_flags);
  }
  else {
      snprintf(srv_string, max_len, "service '%s'%s%s(slot %d, ep %d, pid %d)",
          rpub->label, srv_active_str(rp), srv_version_str(rp),
          slot_nr, rpub->endpoint, rp->r_pid);
  }

#undef srv_str
#undef srv_active_str
#undef srv_version_str
#undef max_len

  return srv_string;
}

/*===========================================================================*
 *			     srv_upd_to_string				     *
 *===========================================================================*/
char* srv_upd_to_string(struct rprocupd *rpupd)
{
   static char srv_upd_string[256];
   struct rprocpub *rpub, *next_rpub, *prev_rpub;
   rpub = rpupd->rp ? rpupd->rp->r_pub : NULL;
   next_rpub = rpupd->next_rpupd && rpupd->next_rpupd->rp ? rpupd->next_rpupd->rp->r_pub : NULL;
   prev_rpub = rpupd->prev_rpupd && rpupd->prev_rpupd->rp ? rpupd->prev_rpupd->rp->r_pub : NULL;

#define srv_ep(RPUB) (RPUB ? (RPUB)->endpoint : -1)
#define srv_upd_luflag_c(F) (rpupd->lu_flags & F ? '1' : '0')
#define srv_upd_iflag_c(F) (rpupd->init_flags & F ? '1' : '0')

   snprintf(srv_upd_string, sizeof(srv_upd_string), "update (lu_flags(SAMPNDRV)="
		"%c%c%c%c%c%c%c%c,"
		" init_flags=(FCTD)=%c%c%c%c, state %d (%s),"
		" tm %u, maxtime %u, endpoint %d,"
		" state_data_gid %d, prev_ep %d, next_ep %d)",
		srv_upd_luflag_c(SEF_LU_SELF), srv_upd_luflag_c(SEF_LU_ASR),
		srv_upd_luflag_c(SEF_LU_MULTI), srv_upd_luflag_c(SEF_LU_PREPARE_ONLY),
		srv_upd_luflag_c(SEF_LU_NOMMAP), srv_upd_luflag_c(SEF_LU_DETACHED),
		srv_upd_luflag_c(SEF_LU_INCLUDES_RS),
		srv_upd_luflag_c(SEF_LU_INCLUDES_VM), srv_upd_iflag_c(SEF_INIT_FAIL),
		srv_upd_iflag_c(SEF_INIT_CRASH), srv_upd_iflag_c(SEF_INIT_TIMEOUT),
		srv_upd_iflag_c(SEF_INIT_DEFCB), rpupd->prepare_state,
		rpupd->prepare_state_data.eval_addr ? rpupd->prepare_state_data.eval_addr : "",
		rpupd->prepare_tm, rpupd->prepare_maxtime, srv_ep(rpub),
		rpupd->prepare_state_data_gid, srv_ep(prev_rpub), srv_ep(next_rpub));

   return srv_upd_string;
}

/*===========================================================================*
 *			     rs_asynsend				     *
 *===========================================================================*/
int rs_asynsend(struct rproc *rp, message *m_ptr, int no_reply)
{
  struct rprocpub *rpub;
  int r;

  if (rp == NULL || rp->r_pub == NULL || m_ptr == NULL) {
      return EINVAL;
  }

  rpub = rp->r_pub;

  if(no_reply) {
      r = asynsend3(rpub->endpoint, m_ptr, AMF_NOREPLY);
  }
  else {
      r = asynsend(rpub->endpoint, m_ptr);
  }

  if(rs_verbose)
      printf("RS: %s being asynsent to with message type %d, noreply=%d, result=%d\n",
          srv_to_string(rp), m_ptr->m_type, no_reply, r);

  return r;
}

/*===========================================================================*
 *			     rs_receive_ticks				     *
 *===========================================================================*/
int rs_receive_ticks(endpoint_t src, message *m_ptr,
    int *status_ptr, clock_t ticks)
{
  ipc_filter_el_t ipc_filter[2];
  clock_t time_left, uptime;
  int r, s, status;

  memset(ipc_filter, 0, sizeof(ipc_filter));
  ipc_filter[0].flags = IPCF_MATCH_M_SOURCE;
  ipc_filter[0].m_source = CLOCK;
  ipc_filter[1].flags = IPCF_MATCH_M_SOURCE;
  ipc_filter[1].m_source = src;

  if ((s = sys_statectl(SYS_STATE_ADD_IPC_WL_FILTER, ipc_filter,
    sizeof(ipc_filter))) != OK)
      panic("RS: rs_receive_ticks: setting IPC filter failed: %d", s);

  if ((s = sys_setalarm2(ticks, FALSE, &time_left, &uptime)) != OK)
      panic("RS: rs_receive_ticks: setting alarm failed: %d", s);

  while ((r = ipc_receive(ANY, m_ptr, &status)) == OK &&
    m_ptr->m_source == CLOCK) {
      if (m_ptr->m_type == NOTIFY_MESSAGE &&
        m_ptr->m_notify.timestamp >= uptime + ticks)
          break;
  }

  if (time_left != TMR_NEVER) {
      if (time_left > ticks)
          time_left -= ticks;
      else
          time_left = 1;

      (void)sys_setalarm(time_left, FALSE);
  }

  if ((s = sys_statectl(SYS_STATE_CLEAR_IPC_FILTERS, NULL, 0)) != OK)
      panic("RS: rs_receive_ticks: setting IPC filter failed: %d", s);

  if (r == OK && m_ptr->m_source == CLOCK)
      return ENOTREADY;

  if (status_ptr != NULL)
      *status_ptr = status;
  return r;
}

/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
void reply(endpoint_t who, struct rproc *rp, message *m_ptr)
{
  int r;

  if(who == RS_PROC_NR) {
      return;
  }

  if(rs_verbose && rp)
      printf("RS: %s being replied to with message type %d\n", srv_to_string(rp), m_ptr->m_type);

  r = ipc_sendnb(who, m_ptr);
  if (r != OK)
      printf("RS: unable to send reply to %d: %d\n", who, r);
}

/*===========================================================================*
 *			      late_reply				     *
 *===========================================================================*/
void late_reply(struct rproc *rp, int code)
{
  if(rp->r_flags & RS_LATEREPLY) {
      message m;
      m.m_type = code;
      if(rs_verbose)
          printf("RS: %s late reply %d to %d for request %d\n",
              srv_to_string(rp), code, rp->r_caller, rp->r_caller_request);

      reply(rp->r_caller, NULL, &m);
      rp->r_flags &= ~RS_LATEREPLY;
  }
}

/*===========================================================================*
 *				rs_isokendpt			 	     *
 *===========================================================================*/
int rs_isokendpt(endpoint_t endpoint, int *proc)
{
	*proc = _ENDPOINT_P(endpoint);
	if(*proc < -NR_TASKS || *proc >= NR_PROCS)
		return EINVAL;

	return OK;
}

/*===========================================================================*
 *				sched_init_proc			 	     *
 *===========================================================================*/
int sched_init_proc(struct rproc *rp)
{
  int s;
  int is_usr_proc;

  is_usr_proc = !(rp->r_priv.s_flags & SYS_PROC);
  if(is_usr_proc) assert(rp->r_scheduler == NONE);
  if(!is_usr_proc) assert(rp->r_scheduler != NONE);

  s = sched_start(rp->r_scheduler, rp->r_pub->endpoint, 
      RS_PROC_NR, rp->r_priority, rp->r_quantum, rp->r_cpu,
      &rp->r_scheduler);

  return s;
}

/*===========================================================================*
 *				update_sig_mgrs			 	     *
 *===========================================================================*/
int update_sig_mgrs(struct rproc *rp, endpoint_t sig_mgr,
	endpoint_t bak_sig_mgr)
{
  int r;
  struct rprocpub *rpub;

  rpub = rp->r_pub;

  if(rs_verbose)
      printf("RS: %s updates signal managers: %d%s / %d\n", srv_to_string(rp),
          sig_mgr == SELF ? rpub->endpoint : sig_mgr,
          sig_mgr == SELF ? "(SELF)" : "",
          bak_sig_mgr == NONE ? -1 : bak_sig_mgr);

  if ((r = sys_getpriv(&rp->r_priv, rpub->endpoint)) != OK) {
      printf("unable to synch privilege structure: %d\n", r);
      return r;
  }

  rp->r_priv.s_sig_mgr = sig_mgr;
  rp->r_priv.s_bak_sig_mgr = bak_sig_mgr;

  r = sys_privctl(rpub->endpoint, SYS_PRIV_UPDATE_SYS, &rp->r_priv);
  if(r != OK) {
      printf("unable to update privilege structure: %d\n", r);
      return r;
  }

  return OK;
}

/*===========================================================================*
 *				rs_is_idle			 	     *
 *===========================================================================*/
int rs_is_idle(void)
{
  int slot_nr;
  struct rproc *rp;
  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      rp = &rproc[slot_nr];
      if (!(rp->r_flags & RS_IN_USE)) {
          continue;
      }
      if(!RS_SRV_IS_IDLE(rp)) {
          return 0;
      }
  }
  return 1;
}

/*===========================================================================*
 *				rs_idle_period				     *
 *===========================================================================*/
void rs_idle_period(void)
{
  struct rproc *rp;
  struct rprocpub *rpub;
  int r;

  if(!shutting_down && !rs_is_idle()) {
      return;
  }

  for (rp=BEG_RPROC_ADDR; rp<END_RPROC_ADDR; rp++) {
      if((rp->r_flags & (RS_IN_USE|RS_DEAD)) == (RS_IN_USE|RS_DEAD)) {
          cleanup_service(rp);
      }
  }

  if (shutting_down) return;

  for (rp=BEG_RPROC_ADDR; rp<END_RPROC_ADDR; rp++) {
      rpub = rp->r_pub;
      if((rp->r_flags & RS_ACTIVE) && (rpub->sys_flags & SF_USE_REPL) && rp->r_next_rp == NULL) {
          if(rpub->endpoint == VM_PROC_NR && (rp->r_old_rp || rp->r_new_rp)) {
              continue;
          }
          if ((r = clone_service(rp, RST_SYS_PROC, 0)) != OK) {
              printf("RS: warning: unable to clone %s (error %d)\n",
                  srv_to_string(rp), r);
          }
      }
  }
}

/*===========================================================================*
 *			   print_services_status		 	     *
 *===========================================================================*/
void print_services_status(void)
{
  int slot_nr;
  struct rproc *rp;
  int num_services = 0;
  int num_service_instances = 0;
  int is_verbose = 1;

  PRINT_SEP();
  printf("Printing information about all the system service instances:\n");
  PRINT_SEP();
  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      rp = &rproc[slot_nr];
      if (!(rp->r_flags & RS_IN_USE)) {
          continue;
      }
      if (rp->r_flags & RS_ACTIVE) {
          num_services++;
      }
      num_service_instances++;
      printf("%s\n", srv_to_string_gen(rp, is_verbose));
  }
  PRINT_SEP();
  printf("Found %d service instances, of which %d are active services\n",
  	  num_service_instances, num_services);
  PRINT_SEP();
}

/*===========================================================================*
 *			    print_update_status 		 	     *
 *===========================================================================*/
void print_update_status(void)
{
  struct rprocupd *prev_rpupd, *rpupd;
  int is_updating = RUPDATE_IS_UPDATING();
  int i;

#define rupdate_flag_c(F) (rupdate.flags & F ? '1' : '0')

  if(!is_updating && !RUPDATE_IS_UPD_SCHEDULED()) {
      PRINT_SEP();
      printf("No update is in progress or scheduled\n");
      PRINT_SEP();
      return;
  }

  PRINT_SEP();
  i = 1;
  printf("A %s-component update is %s, flags(UIRV)=%c%c%c%c:\n", RUPDATE_IS_UPD_MULTI() ? "multi" : "single",
      is_updating ? "in progress" : "scheduled",
      rupdate_flag_c(RS_UPDATING), rupdate_flag_c(RS_INITIALIZING),
      rupdate.rs_rpupd ? '1' : '0', rupdate.vm_rpupd ? '1' : '0');
  PRINT_SEP();
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
      printf("%d. %s %s %s\n", i++, srv_to_string(rpupd->rp),
          is_updating ? "updating with" : "scheduled for",
          srv_upd_to_string(rpupd));
  );
  PRINT_SEP();

#undef rupdate_flag_c
}