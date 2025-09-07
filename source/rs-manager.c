/*
 * Changes:
 *   Nov 22, 2009:	added basic live update support  (Cristiano Giuffrida)
 *   Mar 02, 2009:	Extended isolation policies  (Jorrit N. Herder)
 *   Jul 22, 2005:	Created  (Jorrit N. Herder)
 */

#include <paths.h>
#include <sys/exec_elf.h>
#include "inc.h"
#include "kernel/proc.h"

static int run_script(struct rproc *rp);
static int caller_is_root(endpoint_t endpoint);
static int caller_can_control(endpoint_t endpoint, struct rproc *target_rp);
static char *get_next_name(char *ptr, char *name, const char *caller_label);

/*===========================================================================*
 *				caller_is_root				     *
 *===========================================================================*/
static int caller_is_root(endpoint_t endpoint)
{
  uid_t euid;

  /* Check if caller has root user ID. */
  euid = getnuid(endpoint);
  if (rs_verbose && euid != 0) {
	printf("RS: got unauthorized request from endpoint %d\n", endpoint);
  }
  
  return euid == 0;
}

/*===========================================================================*
 *				caller_can_control			     *
 *===========================================================================*/
static int caller_can_control(endpoint_t endpoint, struct rproc *target_rp)
{
  int control_allowed = 0;
  register struct rproc *rp;
  register struct rprocpub *rpub;
  const char *proc_name;
  int c;

  proc_name = target_rp->r_pub->proc_name;

  /* Check if label is listed in caller's isolation policy. */
  for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
	if (!(rp->r_flags & RS_IN_USE)) {
		continue;
	}

	rpub = rp->r_pub;
	if (rpub->endpoint == endpoint) {
		break;
	}
  }
  if (rp == END_RPROC_ADDR) {
	return 0;
  }

  for (c = 0; c < rp->r_nr_control; c++) {
	if (strcmp(rp->r_control[c], proc_name) == 0) {
		control_allowed = 1;
		break;
	}
  }

  if (rs_verbose) {
	printf("RS: allowing %u control over %s via policy: %s\n",
		endpoint, target_rp->r_pub->label,
		control_allowed ? "yes" : "no");
  }

  return control_allowed;
}

/*===========================================================================*
 *			     check_call_permission			     *
 *===========================================================================*/
int check_call_permission(endpoint_t caller, int call, struct rproc *rp)
{
/* Check if the caller has permission to execute a particular call. */
  struct rprocpub *rpub;
  int call_allowed;

  /* Caller should be either root or have control privileges. */
  call_allowed = caller_is_root(caller);
  if(rp) {
      call_allowed |= caller_can_control(caller, rp);
  }
  if(!call_allowed) {
      return EPERM;
  }

  if(rp) {
      rpub = rp->r_pub;

      /* Only allow RS_EDIT if the target is a user process. */
      if(!(rp->r_priv.s_flags & SYS_PROC)) {
          if(call != RS_EDIT) {
		return EPERM;
	  }
      }

      /* Disallow the call if an update is in progress. */
      if(RUPDATE_IS_UPDATING()) {
      	  return EBUSY;
      }

      /* Disallow the call if another call is in progress for the service. */
      if((rp->r_flags & RS_LATEREPLY)
          || (rp->r_flags & RS_INITIALIZING)) {
          return EBUSY;
      }

      /* Only allow RS_DOWN and RS_RESTART if the service has terminated. */
      if(rp->r_flags & RS_TERMINATED) {
          if(call != RS_DOWN && call != RS_RESTART) {
		return EPERM;
	  }
      }

      /* Disallow RS_DOWN for core system services. */
      if (rpub->sys_flags & SF_CORE_SRV) {
          if(call == RS_DOWN) {
		return EPERM;
	  }
      }
  }

  return OK;
}

/*===========================================================================*
 *				copy_rs_start				     *
 *===========================================================================*/
int copy_rs_start(endpoint_t src_e, char *src_rs_start, struct rs_start *dst_rs_start)
{
  int r;

  r = sys_datacopy(src_e, (vir_bytes) src_rs_start, 
  	SELF, (vir_bytes) dst_rs_start, sizeof(struct rs_start));

  return r;
}

/*===========================================================================*
 *				copy_label				     *
 *===========================================================================*/
int copy_label(endpoint_t src_e, char *src_label, size_t src_len,
	char *dst_label, size_t dst_len)
{
  int s;
  size_t len;

  len = MIN(dst_len - 1, src_len);

  s = sys_datacopy(src_e, (vir_bytes) src_label,
	SELF, (vir_bytes) dst_label, len);
  if (s != OK) {
	return s;
  }

  dst_label[len] = '\0';

  return OK;
}

/*===========================================================================*
 *			      init_state_data				     *
 *===========================================================================*/
int init_state_data(endpoint_t src_e, int prepare_state,
    struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
  int s, i, j, num_ipc_filters = 0;
  struct rs_ipc_filter_el (*rs_ipc_filter_els)[IPCF_MAX_ELEMENTS];
  struct rs_ipc_filter_el rs_ipc_filter[IPCF_MAX_ELEMENTS];
  size_t rs_ipc_filter_size = sizeof(rs_ipc_filter);
  ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS];
  size_t ipcf_els_buff_size;

  dst_rs_state_data->size = 0;
  dst_rs_state_data->eval_addr = NULL;
  dst_rs_state_data->eval_len = 0;
  dst_rs_state_data->ipcf_els = NULL;
  dst_rs_state_data->ipcf_els_size  = 0;
  if(src_rs_state_data->size != sizeof(struct rs_state_data)) {
      return E2BIG;
  }

  /* Initialize eval expression. */
  if(prepare_state == SEF_LU_STATE_EVAL) {
      if(src_rs_state_data->eval_len == 0 || !src_rs_state_data->eval_addr) {
          return EINVAL;
      }
      dst_rs_state_data->eval_addr = malloc(src_rs_state_data->eval_len + 1);
      dst_rs_state_data->eval_len = src_rs_state_data->eval_len;
      if(!dst_rs_state_data->eval_addr) {
          return ENOMEM