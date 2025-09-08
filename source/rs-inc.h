#define _SYSTEM 1

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <lib.h>

#include <minix/callnr.h>
#include <minix/config.h>
#include <minix/type.h>
#include <minix/const.h>
#include <minix/com.h>
#include <minix/syslib.h>
#include <minix/sysinfo.h>
#include <minix/sysutil.h>
#include <minix/bitmap.h>
#include <minix/rs.h>
#include <minix/dmap.h>
#include <minix/endpoint.h>
#include <minix/vm.h>
#include <minix/ds.h>
#include <minix/minlib.h>
#include <minix/sched.h>
#include <minix/priv.h>

#include <machine/archtypes.h>
#include <minix/timers.h>
#include "kernel/priv.h"
#include "kernel/ipc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "const.h"
#include "type.h"
#include "glo.h"

extern int do_sef_lu_request(message *m_ptr);