#ifndef RS_GLO_H
#define RS_GLO_H

#ifdef _TABLE
#undef EXTERN
#define EXTERN
#endif

#ifndef EXTERN
#define EXTERN extern
#endif

#include <minix/param.h>

#ifdef __cplusplus
extern "C" {
#endif

extern struct boot_image_priv boot_image_priv_table[];
extern struct boot_image_sys boot_image_sys_table[];
extern struct boot_image_dev boot_image_dev_table[];

EXTERN struct rprocpub rprocpub[NR_SYS_PROCS];
EXTERN struct rproc rproc[NR_SYS_PROCS];
EXTERN struct rproc *rproc_ptr[NR_PROCS];

EXTERN sef_init_info_t rinit;
EXTERN struct rupdate rupdate;

EXTERN long rs_verbose;

EXTERN int shutting_down;

EXTERN unsigned system_hz;

EXTERN struct machine machine;

#ifdef __cplusplus
}
#endif

#endif /* RS_GLO_H */