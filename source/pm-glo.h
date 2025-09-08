#ifndef PM_GLOBALS_H
#define PM_GLOBALS_H

#ifndef EXTERN
#define EXTERN extern
#endif

#ifdef _TABLE
#undef EXTERN
#define EXTERN
#endif

struct mproc;
struct machine;
struct utsname;

EXTERN struct mproc *mp;
EXTERN int procs_in_use;
EXTERN char monitor_params[MULTIBOOT_PARAM_BUF_SIZE];

extern struct utsname uts_val;

EXTERN message m_in;
EXTERN int who_p;
EXTERN int who_e;
EXTERN int call_nr;

extern int (*const call_vec[])(void);
EXTERN sigset_t core_sset;
EXTERN sigset_t ign_sset;
EXTERN sigset_t noign_sset;

EXTERN u32_t system_hz;
EXTERN int abort_flag;

EXTERN struct machine machine;
#ifdef CONFIG_SMP
EXTERN int cpu_proc[CONFIG_MAX_CPUS];
#endif

#endif