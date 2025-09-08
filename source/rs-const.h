#ifndef RS_CONST_H
#define RS_CONST_H

#define DEBUG_DEFAULT 0
#define PRIV_DEBUG_DEFAULT 0

#ifndef DEBUG
#define DEBUG DEBUG_DEFAULT
#endif

#ifndef PRIV_DEBUG
#define PRIV_DEBUG PRIV_DEBUG_DEFAULT
#endif

#define MAX_COMMAND_LEN 512
#define MAX_SCRIPT_LEN 256
#define MAX_NR_ARGS 10
#define MAX_IPC_LIST 256
#define MAX_DET_RESTART 10

#define RS_IN_USE 0x001
#define RS_EXITING 0x002
#define RS_REFRESHING 0x004
#define RS_NOPINGREPLY 0x008
#define RS_TERMINATED 0x010
#define RS_LATEREPLY 0x020
#define RS_INITIALIZING 0x040
#define RS_UPDATING 0x080
#define RS_PREPARE_DONE 0x100
#define RS_INIT_DONE 0x200
#define RS_INIT_PENDING 0x400
#define RS_ACTIVE 0x800
#define RS_DEAD 0x1000
#define RS_CLEANUP_DETACH 0x2000
#define RS_CLEANUP_SCRIPT 0x4000
#define RS_REINCARNATE 0x8000

#define RS_SRV_IS_IDLE(S) (((S)->r_flags & (RS_DEAD | ~RS_IN_USE | ~RS_ACTIVE | ~RS_CLEANUP_DETACH | ~RS_CLEANUP_SCRIPT)) == RS_DEAD)

#define RS_INIT_T (system_hz * 10)
#define RS_DELTA_T (system_hz)
#define BACKOFF_BITS (sizeof(long) * 8)
#define MAX_BACKOFF 30

#define BEG_RPROC_ADDR (&rproc[0])
#define END_RPROC_ADDR (&rproc[NR_SYS_PROCS])

#define RS_DEFAULT_PREPARE_MAXTIME (2 * RS_DELTA_T)

#define NULL_BOOT_NR NR_BOOT_PROCS
#define DEFAULT_BOOT_NR NR_BOOT_PROCS

#define SRV_SF SF_CORE_SRV
#define SRVR_SF (SRV_SF | SF_NEED_REPL)
#define DSRV_SF 0
#define VM_SF SRVR_SF

#define SRV_OR_USR(rp, X, Y) ((rp)->r_priv.s_flags & SYS_PROC ? (X) : (Y))

#define RS_DONTREPLY 0
#define RS_REPLY 1
#define RS_CANCEL 2

#define RS_DONTSWAP 0
#define RS_SWAP 1

#define RS_VM_DEFAULT_MAP_PREALLOC_LEN (1024 * 1024 * 8)
#define RS_USE_PAGING 0

#define RUPDATE_INIT() memset(&rupdate, 0, sizeof(rupdate))
#define RUPDATE_CLEAR() RUPDATE_INIT()

#define RUPDATE_ITER(HEAD, RPUPD_PREV, RPUPD, B)                   \
    for ((RPUPD) = (HEAD), (RPUPD_PREV) = NULL; (RPUPD) != NULL;   \
         (RPUPD_PREV) = (RPUPD), (RPUPD) = (RPUPD)->next_rpupd) {  \
        B                                                          \
    }

#define RUPDATE_REV_ITER(TAIL, RPUPD_PREV, RPUPD, B)       \
    for ((RPUPD) = (TAIL); (RPUPD) != NULL;                \
         (RPUPD_PREV) = (RPUPD)->prev_rpupd, (RPUPD) = (RPUPD)->prev_rpupd) {  \
        B                                                 \
    }

#define RUPDATE_IS_UPDATING() ((rupdate.flags & RS_UPDATING) != 0)
#define RUPDATE_IS_VM_UPDATING() (RUPDATE_IS_UPDATING() && rupdate.vm_rpupd)
#define RUPDATE_IS_VM_INIT_DONE() ((rproc_ptr[_ENDPOINT_P(VM_PROC_NR)]->r_flags & RS_INIT_DONE) != 0)
#define RUPDATE_IS_RS_UPDATING() (RUPDATE_IS_UPDATING() && rupdate.rs_rpupd)
#define RUPDATE_IS_RS_INIT_DONE() ((rproc_ptr[_ENDPOINT_P(RS_PROC_NR)]->r_flags & RS_INIT_DONE) != 0)
#define RUPDATE_IS_INITIALIZING() ((rupdate.flags & RS_INITIALIZING) != 0)
#define RUPDATE_IS_UPD_SCHEDULED() ((rupdate.num_rpupds > 0) && !RUPDATE_IS_UPDATING())
#define RUPDATE_IS_UPD_MULTI() (rupdate.num_rpupds > 1)
#define RUPDATE_IS_UPD_VM_MULTI() (rupdate.vm_rpupd && RUPDATE_IS_UPD_MULTI())
#define SRV_IS_UPDATING(RP) (((RP)->r_flags & RS_UPDATING) != 0)
#define SRV_IS_UPDATING_AND_INITIALIZING(RP) (((RP)->r_flags & (RS_UPDATING | RS_INITIALIZING)) == (RS_UPDATING | RS_INITIALIZING))
#define UPD_INIT_MAXTIME(RPUPD) ((RPUPD)->prepare_maxtime != RS_DEFAULT_PREPARE_MAXTIME ? (RPUPD)->prepare_maxtime : RS_INIT_T)
#define UPD_IS_PREPARING_ONLY(RPUPD) (((RPUPD)->lu_flags & SEF_LU_PREPARE_ONLY) != 0)
#define SRV_IS_PREPARING_ONLY(RP) ((RP)->r_upd.rp && UPD_IS_PREPARING_ONLY(&(RP)->r_upd))
#define UPD_IS_UPD_SCHEDULED(RPUPD) (RUPDATE_IS_UPD_SCHEDULED() && (RPUPD)->rp)
#define SRV_IS_UPD_SCHEDULED(RP) UPD_IS_UPD_SCHEDULED(&(RP)->r_upd)

#endif