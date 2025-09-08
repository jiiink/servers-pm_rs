#include "inc.h"
#include <assert.h>
#include <sys/exec.h>
#include <libexec.h>
#include <machine/vmparam.h>

static int do_exec(int proc_e, char *exec, size_t exec_len, char *progname,
	char *frame, size_t frame_len, vir_bytes ps_str);
static int exec_restart(int proc_e, int result, vir_bytes pc, vir_bytes ps_str);
static int read_seg(struct exec_info *execi, off_t off,
        vir_bytes seg_addr, size_t seg_bytes);

/* Array of loaders for different object formats */
static struct exec_loaders {
	libexec_exec_loadfunc_t load_object;
} const exec_loaders[] = {
	{ libexec_load_elf },
	{ NULL }
};

int srv_execve(int proc_e, char *exec, size_t exec_len, char *progname,
	char **argv, char **envp)
{
	size_t frame_size = 0;	/* Size of the new initial stack. */
	int argc = 0;		/* Argument count. */
	int envc = 0;		/* Environment count */
	char overflow = 0;	/* No overflow yet. */
	char *frame;
	struct ps_strings *psp;
	int vsp = 0;	/* (virtual) Stack pointer in new address space. */

	int r;

	minix_stack_params(argv[0], argv, envp, &frame_size, &overflow,
		&argc, &envc);

	/* The party is off if there is an overflow. */
	if (overflow) {
		errno = E2BIG;
		return -1;
	}

	/* Allocate space for the stack frame. */
	if ((frame = (char *) sbrk(frame_size)) == (char *) -1) {
		errno = E2BIG;
		return -1;
	}

	minix_stack_fill(argv[0], argc, argv, envc, envp, frame_size, frame,
		&vsp, &psp);

	r = do_exec(proc_e, exec, exec_len, progname, frame, frame_size,
		(vir_bytes)((vir_bytes)vsp + (vir_bytes)((char *)psp - frame)));

	/* Failure, return the memory used for the frame and exit. */
	(void) sbrk(-frame_size);

	return r;
}


static int do_exec(int proc_e, char *exec, size_t exec_len, char *progname,
	char *frame, size_t frame_len, vir_bytes ps_str)
{
	int r = ENOEXEC;
	vir_bytes vsp;
	struct exec_info execi;
	size_t i;

	memset(&execi, 0, sizeof(execi));

	execi.stack_high = minix_get_user_sp();
	execi.stack_size = DEFAULT_STACK_LIMIT;
	execi.proc_e = proc_e;
	execi.hdr = exec;
	execi.filesize = execi.hdr_len = exec_len;
	strncpy(execi.progname, progname, PROC_NAME_LEN-1);
	execi.progname[PROC_NAME_LEN-1] = '\0';
	execi.frame_len = frame_len;

	/* callback functions and data */
	execi.copymem = read_seg;
	execi.clearproc = libexec_clearproc_vm_procctl;
	execi.clearmem = libexec_clear_sys_memset;
	execi.allocmem_prealloc_cleared = libexec_alloc_mmap_prealloc_cleared;
	execi.allocmem_prealloc_junk = libexec_alloc_mmap_prealloc_junk;
	execi.allocmem_ondemand = libexec_alloc_mmap_ondemand;

	for (i = 0; exec_loaders[i].load_object != NULL; i++) {
		r = (*exec_loaders[i].load_object)(&execi);
		if (r == OK) break;
	}

	/* No exec loader could load the object */
	if (r != OK) {
	    printf("RS: do_exec: loading error %d\n", r);
	    return r;
	}

	/* Inform PM */
        if((r = libexec_pm_newexec(execi.proc_e, &execi)) != OK)
		return r;

	/* Patch up stack and copy it from RS to new core image. */
	vsp = execi.stack_high - (vir_bytes)frame_len;
	r = sys_datacopy(SELF, (vir_bytes) frame,
		proc_e, (vir_bytes) vsp, (phys_bytes)frame_len);
	if (r != OK) {
		printf("RS: do_exec: copying out new stack failed: %d\n", r);
		(void)exec_restart(proc_e, r, execi.pc, ps_str);
		return r;
	}

	return exec_restart(proc_e, OK, execi.pc, ps_str);
}

static int exec_restart(int proc_e, int result, vir_bytes pc, vir_bytes ps_str)
{
	int r;
	message m;

	memset(&m, 0, sizeof(m));
	m.m_type = PM_EXEC_RESTART;
	m.m_rs_pm_exec_restart.endpt = proc_e;
	m.m_rs_pm_exec_restart.result = result;
	m.m_rs_pm_exec_restart.pc = pc;
	m.m_rs_pm_exec_restart.ps_str = ps_str;

	r = ipc_sendrec(PM_PROC_NR, &m);
	if (r != OK)
		return r;

	return m.m_type;
}

static int read_seg(
struct exec_info *execi,       /* various data needed for exec */
off_t off,                     /* offset in file */
vir_bytes seg_addr,            /* address to load segment */
size_t seg_bytes               /* how much is to be transferred? */
)
{
	int r;

	if (off < 0) return ENOEXEC;

	if ((size_t)off > execi->hdr_len) return ENOEXEC;

	{
		size_t avail = execi->hdr_len - (size_t)off;
		if (seg_bytes > avail) return ENOEXEC;
	}

	r = sys_datacopy(SELF, (vir_bytes)((char *)execi->hdr + (size_t)off),
  		execi->proc_e, seg_addr, seg_bytes);
	if (r != OK) {
		printf("RS: exec read_seg: copy 0x%lx bytes into %d at 0x%08lx failed: %d\n",
			(unsigned long) seg_bytes, execi->proc_e,
			(unsigned long) seg_addr, r);
	}
	return r;
}