#include "inc.h"
#include <assert.h>
#include <sys/exec.h>
#include <libexec.h>
#include <machine/vmparam.h>

static int do_exec(int proc_e, char *exec, size_t exec_len, char *progname,
        char *frame, int frame_len, vir_bytes ps_str);
static int exec_restart(int proc_e, int result, vir_bytes pc, vir_bytes ps_str);
static int read_seg(struct exec_info *execi, off_t off,
        vir_bytes seg_addr, size_t seg_bytes);

static const struct exec_loaders {
	libexec_exec_loadfunc_t load_object;
} exec_loaders[] = {
	{ libexec_load_elf },
	{ NULL }
};

static int allocate_stack_frame(char **frame, size_t frame_size) {
	*frame = (char *) sbrk(frame_size);
	if (*frame == (char *) -1) {
		errno = E2BIG;
		return -1;
	}
	return 0;
}

int srv_execve(int proc_e, char *exec, size_t exec_len, char *progname,
	char **argv, char **envp) {
	size_t frame_size = 0;
	int argc = 0, envc = 0;
	char overflow = 0;
	char *frame;
	struct ps_strings *psp;
	int vsp = 0;
	int result;

	minix_stack_params(argv[0], argv, envp, &frame_size, &overflow, &argc, &envc);

	if (overflow) {
		errno = E2BIG;
		return -1;
	}

	if (allocate_stack_frame(&frame, frame_size) != 0) {
		return -1;
	}

	minix_stack_fill(argv[0], argc, argv, envc, envp, frame_size, frame, &vsp, &psp);

	result = do_exec(proc_e, exec, exec_len, progname, frame, frame_size, vsp + ((char *)psp - frame));

	(void) sbrk(-frame_size);
	return result;
}

static int do_exec(int proc_e, char *exec, size_t exec_len, char *progname,
	char *frame, int frame_len, vir_bytes ps_str) {
	int r;
	vir_bytes vsp;
	struct exec_info execi;
	int i;

	memset(&execi, 0, sizeof(execi));

	execi.stack_high = minix_get_user_sp();
	execi.stack_size = DEFAULT_STACK_LIMIT;
	execi.proc_e = proc_e;
	execi.hdr = exec;
	execi.filesize = execi.hdr_len = exec_len;
	strncpy(execi.progname, progname, PROC_NAME_LEN - 1);
	execi.progname[PROC_NAME_LEN - 1] = '\0';
	execi.frame_len = frame_len;

	execi.copymem = read_seg;
	execi.clearproc = libexec_clearproc_vm_procctl;
	execi.clearmem = libexec_clear_sys_memset;
	execi.allocmem_prealloc_cleared = libexec_alloc_mmap_prealloc_cleared;
	execi.allocmem_prealloc_junk = libexec_alloc_mmap_prealloc_junk;
	execi.allocmem_ondemand = libexec_alloc_mmap_ondemand;

	for (i = 0; exec_loaders[i].load_object != NULL; i++) {
		r = exec_loaders[i].load_object(&execi);
		if (r == OK) break;
	}

	if (r != OK) {
		printf("RS: do_exec: loading error %d\n", r);
		return r;
	}

	if ((r = libexec_pm_newexec(execi.proc_e, &execi)) != OK) return r;

	vsp = execi.stack_high - frame_len;
	r = sys_datacopy(SELF, (vir_bytes)frame, proc_e, (vir_bytes)vsp, (phys_bytes)frame_len);
	if (r != OK) {
		printf("do_exec: copying out new stack failed: %d\n", r);
		exec_restart(proc_e, r, execi.pc, ps_str);
		return r;
	}

	return exec_restart(proc_e, OK, execi.pc, ps_str);
}

static int exec_restart(int proc_e, int result, vir_bytes pc, vir_bytes ps_str) {
	int r;
	message m;

	memset(&m, 0, sizeof(m));
	m.m_type = PM_EXEC_RESTART;
	m.m_rs_pm_exec_restart.endpt = proc_e;
	m.m_rs_pm_exec_restart.result = result;
	m.m_rs_pm_exec_restart.pc = pc;
	m.m_rs_pm_exec_restart.ps_str = ps_str;

	r = ipc_sendrec(PM_PROC_NR, &m);
	if (r != OK) return r;

	return m.m_type;
}

static int read_seg(struct exec_info *execi, off_t off, vir_bytes seg_addr, size_t seg_bytes) {
	int r;

	if (off + seg_bytes > execi->hdr_len) return ENOEXEC;
	r = sys_datacopy(SELF, ((vir_bytes)execi->hdr) + off, execi->proc_e, seg_addr, seg_bytes);
	if (r != OK) {
		printf("RS: exec read_seg: copy 0x%x bytes into %i at 0x%08lx failed: %i\n", (int)seg_bytes, execi->proc_e, seg_addr, r);
	}
	return r;
}