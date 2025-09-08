#ifndef RS_TYPE_H
#define RS_TYPE_H

#include <stddef.h>

struct boot_image_priv {
  endpoint_t endpoint;
  char label[RS_MAX_LABEL_LEN];
  int flags;
};

struct boot_image_sys {
  endpoint_t endpoint;
  int flags;
};

struct boot_image_dev {
  endpoint_t endpoint;
  dev_t dev_nr;
};

struct rproc;
struct rprocupd {
  int lu_flags;
  int init_flags;
  int prepare_state;
  endpoint_t state_endpoint;
  clock_t prepare_tm;
  clock_t prepare_maxtime;
  struct rproc *rp;
  struct rs_state_data prepare_state_data;
  cp_grant_id_t prepare_state_data_gid;
  struct rprocupd *prev_rpupd;
  struct rprocupd *next_rpupd;
};

struct rupdate {
  int flags;
  int num_rpupds;
  int num_init_ready_pending;
  struct rprocupd *curr_rpupd;
  struct rprocupd *first_rpupd;
  struct rprocupd *last_rpupd;
  struct rprocupd *vm_rpupd;
  struct rprocupd *rs_rpupd;
};

typedef struct priv ixfer_priv_s;
struct rproc {
  struct rprocpub *r_pub;
  struct rproc *r_old_rp;
  struct rproc *r_new_rp;
  struct rproc *r_prev_rp;
  struct rproc *r_next_rp;
  struct rprocupd r_upd;
  pid_t r_pid;
  int r_asr_count;
  int r_restarts;
  long r_backoff;
  unsigned r_flags;
  int r_init_err;
  long r_period;
  clock_t r_check_tm;
  clock_t r_alive_tm;
  clock_t r_stop_tm;
  endpoint_t r_caller;
  int r_caller_request;
  char r_cmd[MAX_COMMAND_LEN];
  char r_args[MAX_COMMAND_LEN];
  char *r_argv[MAX_NR_ARGS + 2]; // path, args, null
  int r_argc;
  char r_script[MAX_SCRIPT_LEN];
  char *r_exec;
  size_t r_exec_len;
  ixfer_priv_s r_priv;
  uid_t r_uid;
  endpoint_t r_scheduler;
  int r_priority;
  int r_quantum;
  int r_cpu;
  vir_bytes r_map_prealloc_addr;
  size_t r_map_prealloc_len;
  struct io_range r_io_tab[NR_IO_RANGE];
  int r_nr_io_range;
  int r_irq_tab[NR_IRQ];
  int r_nr_irq;
  char r_ipc_list[MAX_IPC_LIST];
  int r_nr_control;
  char r_control[RS_NR_CONTROL][RS_MAX_LABEL_LEN];
};

#endif /* RS_TYPE_H */