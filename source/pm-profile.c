#include <minix/config.h>
#include <minix/profile.h>
#include "pm.h"
#include <sys/wait.h>
#include <minix/callnr.h>
#include <minix/com.h>
#include <signal.h>
#include "mproc.h"

int do_sprofile(void)
{
#if SPROFILE
    int action = m_in.m_lc_pm_sprof.action;
    if (action == PROF_START) {
        return sys_sprof(PROF_START, m_in.m_lc_pm_sprof.mem_size,
                         m_in.m_lc_pm_sprof.freq, m_in.m_lc_pm_sprof.intr_type, who_e,
                         m_in.m_lc_pm_sprof.ctl_ptr, m_in.m_lc_pm_sprof.mem_ptr);
    } else if (action == PROF_STOP) {
        return sys_sprof(PROF_STOP, 0, 0, 0, 0, 0, 0);
    } else {
        return EINVAL;
    }
#else
    return ENOSYS;
#endif
}