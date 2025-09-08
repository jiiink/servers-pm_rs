#include "inc.h"
#include <assert.h>
#include <sys/exec.h>
#include <libexec.h>
#include <machine/vmparam.h>

static int do_exec_internal(endpoint_t proc_e, char *exec_hdr, size_t exec_len, char *progname,
	char *frame, int frame_len, vir_bytes ps_str_addr);
static int exec_restart_pm(endpoint_t proc_e, int result, vir_bytes pc, vir_bytes ps_str_addr);
static int read_seg(struct exec_info *execi, off_t off,
        vir_bytes seg_addr, size_t seg_bytes);

/* Array of loaders for different object formats */
static struct exec_loaders {
	libexec_exec_loadfunc_t load_object;
} const exec_loaders[] = {
	{ libexec_load_elf },
	{ NULL } /* Sentinel */
};

/*===========================================================================*
 *				srv_execve				     *
 *===========================================================================*/
int srv_execve(endpoint_t proc_e, char *exec_hdr, size_t exec_len, char *progname,
	char **argv, char **envp)
{
	size_t frame_size = 0;	/* Size of the new initial stack. */
	char overflow = 0;	/* Flag for stack overflow. */
	char *frame;        	/* Pointer to the allocated stack frame. */
	int argc = 0;		/* Argument count. */
	int envc = 0;		/* Environment count. */
	struct ps_strings *psp; /* Pointer to ps_strings structure in stack frame. */
	vir_bytes vsp_ps_strings_offset = 0; /* Virtual address of ps_strings in new address space. */

	int r;

	/* Calculate the required stack frame size and count args/env. */
	minix_stack_params(argv[0], argv, envp, &frame_size, &overflow,
		&argc, &envc);

	/* The party is off if there is an overflow. */
	if (overflow) {
		errno = E2BIG;
		return -1;
	}

	/* Allocate space for the stack frame in RS's memory. */
	if ((frame = (char *) sbrk(frame_size)) == (char *) -1) {
		errno = E2BIG;
		return -1;
	}

	/* Fill the stack frame with argc, argv, envp, and ps_strings. */
	minix_stack_fill(argv[0], argc, argv, envc, envp, frame_size, frame,
		(vir_bytes *)&vsp_ps_strings_offset, &psp);

	/* Perform the actual exec. */
	r = do_exec_internal(proc_e, exec_hdr, exec_len, progname, frame, frame_size,
		(vir_bytes)vsp_ps_strings_offset + ((char *)psp - frame));

	/* Clean up: return the memory used for the stack frame. */
	(void) sbrk(-(ssize_t)frame_size);

	return r;
}

/*===========================================================================*
 *				do_exec_internal			     *
 *===========================================================================*/
static int do_exec_internal(endpoint_t proc_e, char *exec_hdr, size_t exec_len, char *progname,
	char *frame, int frame_len, vir_bytes ps_str_addr)
{
	int r;
	vir_bytes vsp;
	struct exec_info execi;
	int i;

	memset(&execi, 0, sizeof(execi));

	execi.stack_high = minix_get_user_sp(); /* Get the high address for user stack */
	execi.stack_size = DEFAULT_STACK_LIMIT;
	execi.proc_e = proc_e;
	execi.hdr = exec_hdr;
	execi.filesize = execi.hdr_len = exec_len;
	(void)strncpy(execi.progname, progname, sizeof(execi.progname)-1);
	execi.progname[sizeof(execi.progname)-1] = '\0';
	execi.frame_len = frame_len;

	/* callback functions and data */
	execi.copymem = read_seg;
	execi.clearproc = libexec_clearproc_vm_procctl; /* VM to clear process' memory */
	execi.clearmem = libexec_clear_sys_memset;     /* Sys_memset to zero-fill */
	execi.allocmem_prealloc_cleared = libexec_alloc_mmap_prealloc_cleared;
	execi.allocmem_prealloc_junk = libexec_alloc_mmap_prealloc_junk;
	execi.allocmem_ondemand = libexec_alloc_mmap_ondemand;

	/* Try each exec loader to load the object. */
	for(i = 0; exec_loaders[i].load_object != NULL; i++) {
	    r = (*exec_loaders[i].load_object)(&execi);
	    if (r == OK) break; /* Loaded successfully */
	}

	/* No exec loader could load the object. */
	if (r != OK) {
	    printf("RS: do_exec_internal: loading error %d for endpoint %d\n", r, proc_e);
	    return r;
	}

	/* Inform PM that a new executable is being loaded. */
    if((r = libexec_pm_newexec(execi.proc_e, &execi)) != OK) {
		printf("RS: libexec_pm_newexec failed for endpoint %d: %d\n", proc_e, r);
		return r;
	}

	/* Patch up stack pointer and copy the stack frame from RS to new core image. */
	vsp = execi.stack_high - frame_len;
	r = sys_datacopy(SELF, (vir_bytes) frame,
		proc_e, (vir_bytes) vsp, (phys_bytes)frame_len);
	if (r != OK) {
		printf("RS: do_exec_internal: copying out new stack for endpoint %d failed: %d\n", proc_e, r);
		exec_restart_pm(proc_e, r, execi.pc, ps_str_addr); /* Inform PM about the failure */
		return r;
	}

	/* Inform PM to restart the process with the new PC and SP. */
	return exec_restart_pm(proc_e, OK, execi.pc, ps_str_addr);
}

/*===========================================================================*
 *				exec_restart_pm				     *
 *===========================================================================*/
static int exec_restart_pm(endpoint_t proc_e, int result, vir_bytes pc, vir_bytes ps_str_addr)
{
	int r;
	message m;

	memset(&m, 0, sizeof(m));
	m.m_type = PM_EXEC_RESTART;
	m.m_rs_pm_exec_restart.endpt = proc_e;
	m.m_rs_pm_exec_restart.result = result;
	m.m_rs_pm_exec_restart.pc = pc;
	m.m_rs_pm_exec_restart.ps_str = ps_str_addr;

	r = ipc_sendrec(PM_PROC_NR, &m);
	if (r != OK) {
		printf("RS: ipc_sendrec to PM for EXEC_RESTART failed: %d\n", r);
		return r;
	}

	return m.m_type; /* Return status from PM */
}

/*===========================================================================*
 *                             read_seg                                     *
 *===========================================================================*/
static int read_seg(
struct exec_info *execi,       /* various data needed for exec */
off_t off,                     /* offset in file */
vir_bytes seg_addr,            /* address to load segment */
size_t seg_bytes           /* how much is to be transferred? */
)
{
/*
 * The byte count on read is usually smaller than the segment count, because
 * a segment is padded out to a click multiple, and the data segment is only
 * partially initialized.
 */
  int r;

  if (off < 0 || off + seg_bytes > execi->hdr_len) {
	printf("RS: exec read_seg: invalid offset (0x%lx) or size (0x%zx) for header length (0x%zx)\n",
		(unsigned long)off, seg_bytes, execi->hdr_len);
	return ENOEXEC;
  }
  if((r = sys_datacopy(SELF, ((vir_bytes)execi->hdr) + off,
  	execi->proc_e, seg_addr, seg_bytes)) != OK) {
	printf("RS: exec read_seg: copy 0x%zx bytes from 0x%lx into %i at 0x%lx failed: %i\n",
		seg_bytes, ((unsigned long)execi->hdr) + off, execi->proc_e, (unsigned long)seg_addr, r);
  }
  return r;
}