#include "pm.h"
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <minix/com.h>
#include <minix/vm.h>
#include "mproc.h"

int handle_mcontext(int (*sys_func)(endpoint_t, void *), endpoint_t endpoint, void *ctx) {
    if(sys_func == NULL || ctx == NULL) {
        return EINVAL;
    }
    return sys_func(endpoint, ctx);
}

int do_setmcontext(void) {
    return handle_mcontext(sys_setmcontext, who_e, m_in.m_lc_pm_mcontext.ctx);
}

int do_getmcontext(void) {
    return handle_mcontext(sys_getmcontext, who_e, m_in.m_lc_pm_mcontext.ctx);
}