#include "pm.h"
#include <minix/callnr.h>
#include <minix/endpoint.h>
#include <minix/com.h>
#include <minix/vm.h>
#include "mproc.h"


/*===========================================================================*
 *				do_setmcontext				     *
 *===========================================================================*/
int
do_setmcontext(void)
{
  /* Forward the system call to the kernel. `who_e` is the endpoint
   * of the calling process, and `m_lc_pm_mcontext.ctx` is the virtual
   * address of the mcontext structure in the caller's address space. */
  return sys_setmcontext(who_e, (const struct __mcontext *)m_in.m_lc_pm_mcontext.ctx);
}


/*===========================================================================*
 *				do_getmcontext				     *
 *===========================================================================*/
int
do_getmcontext(void)
{
  /* Forward the system call to the kernel. `who_e` is the endpoint
   * of the calling process, and `m_lc_pm_mcontext.ctx` is the virtual
   * address where the kernel should copy the mcontext structure. */
  return sys_getmcontext(who_e, (struct __mcontext *)m_in.m_lc_pm_mcontext.ctx);
}