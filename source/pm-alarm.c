#include "pm.h"
#include <signal.h>
#include <sys/time.h>
#include <minix/com.h>
#include <minix/callnr.h>
#include <assert.h>
#include "mproc.h"

#define US 1000000UL

static clock_t ticks_from_timeval(const struct timeval *tv);
static void timeval_from_ticks(struct timeval *tv, clock_t ticks);
static int is_sane_timeval(const struct timeval *tv);
static void getset_vtimer(struct mproc *mp, int nwhich, const struct itimerval *value, struct itimerval *ovalue);
static void get_realtimer(struct mproc *mp, struct itimerval *value);
static void set_realtimer(struct mproc *mp, const struct itimerval *value);
static void cause_sigalrm(int arg);
static int vtimer_num_from_which(int which);

static clock_t ticks_from_timeval(const struct timeval *tv)
{
  unsigned long long ticks64, sec, usec, hz;

  hz = (unsigned long long) system_hz;
  sec = (unsigned long long) (unsigned long) tv->tv_sec;
  usec = (unsigned long long) (unsigned long) tv->tv_usec;

  ticks64 = sec * hz;
  if (hz != 0 && (ticks64 / hz) != sec) {
	ticks64 = LONG_MAX;
  } else {
	unsigned long long add = (hz * usec + (US - 1)) / US;
	ticks64 += add;
	if (ticks64 > (unsigned long long) LONG_MAX) ticks64 = LONG_MAX;
  }

  return (clock_t) ticks64;
}

static void timeval_from_ticks(struct timeval *tv, clock_t ticks)
{
  unsigned long long t = (unsigned long long) (ticks < 0 ? 0 : ticks);
  unsigned long long hz = (unsigned long long) system_hz;

  tv->tv_sec = (long) (t / hz);
  tv->tv_usec = (long) (((t % hz) * (unsigned long long) US) / hz);
}

static int is_sane_timeval(const struct timeval *tv)
{
  return (tv->tv_sec >= 0 && tv->tv_sec <= MAX_SECS &&
          tv->tv_usec >= 0 && tv->tv_usec < (long) US);
}

int do_itimer(void)
{
  struct itimerval ovalue, value;
  int setval, getval;
  int r, which;

  which = m_in.m_lc_pm_itimer.which;
  if (which < 0 || which >= NR_ITIMERS) return EINVAL;

  setval = (m_in.m_lc_pm_itimer.value != 0);
  getval = (m_in.m_lc_pm_itimer.ovalue != 0);

  if (!setval && !getval) return EINVAL;

  if (setval) {
	r = sys_datacopy(who_e, m_in.m_lc_pm_itimer.value,
		PM_PROC_NR, (vir_bytes) &value, (phys_bytes) sizeof(value));
	if (r != OK) return r;

	if (!is_sane_timeval(&value.it_value) ||
	    !is_sane_timeval(&value.it_interval))
		return EINVAL;
  }

  switch (which) {
  	case ITIMER_REAL:
  		if (getval) get_realtimer(mp, &ovalue);
  		if (setval) set_realtimer(mp, &value);
  		r = OK;
  		break;

  	case ITIMER_VIRTUAL:
  	case ITIMER_PROF:
		getset_vtimer(mp, which, setval ? &value : NULL,
			getval ? &ovalue : NULL);
  		r = OK;
  		break;

	default:
		panic("invalid timer type: %d", which);
  }

  if (r == OK && getval) {
	r = sys_datacopy(PM_PROC_NR, (vir_bytes) &ovalue,
		who_e, m_in.m_lc_pm_itimer.ovalue,
		(phys_bytes) sizeof(ovalue));
  }

  return r;
}

static int vtimer_num_from_which(int which)
{
  switch (which) {
    case ITIMER_VIRTUAL: return VT_VIRTUAL;
    case ITIMER_PROF:    return VT_PROF;
    default:             return -1;
  }
}

static void getset_vtimer(struct mproc *rmp, int which, const struct itimerval *value, struct itimerval *ovalue)
{
  clock_t newticks, *nptr = NULL;
  clock_t oldticks, *optr = NULL;
  int r, num;

  if (ovalue != NULL) {
  	optr = &oldticks;
  	timeval_from_ticks(&ovalue->it_interval, rmp->mp_interval[which]);
  }

  if (value != NULL) {
  	newticks = ticks_from_timeval(&value->it_value);
  	nptr = &newticks;

  	if (newticks <= 0)
  		rmp->mp_interval[which] = 0;
	else
		rmp->mp_interval[which] = ticks_from_timeval(&value->it_interval);
  }

  num = vtimer_num_from_which(which);
  if (num < 0) panic("invalid vtimer type: %d", which);

  r = sys_vtimer(rmp->mp_endpoint, num, nptr, optr);
  if (r != OK) panic("sys_vtimer failed: %d", r);

  if (ovalue != NULL) {
  	if (oldticks <= 0) oldticks = rmp->mp_interval[which];
	timeval_from_ticks(&ovalue->it_value, oldticks);
  }
}

void check_vtimer(int proc_nr, int sig)
{
  struct mproc *rmp = &mproc[proc_nr];
  int which, num;

  switch (sig) {
    case SIGVTALRM: which = ITIMER_VIRTUAL; break;
    case SIGPROF:   which = ITIMER_PROF;    break;
    default: panic("invalid vtimer signal: %d", sig);
  }

  num = vtimer_num_from_which(which);
  if (num < 0) panic("invalid vtimer type: %d", which);

  if (rmp->mp_interval[which] > 0)
  	sys_vtimer(rmp->mp_endpoint, num, &rmp->mp_interval[which], NULL);
}

static void get_realtimer(struct mproc *rmp, struct itimerval *value)
{
  clock_t exptime, uptime, remaining;

  if (rmp->mp_flags & ALARM_ON) {
	uptime = getticks();
	exptime = tmr_exp_time(&rmp->mp_timer);
  	remaining = exptime - uptime;
  	if (remaining <= 0) remaining = rmp->mp_interval[ITIMER_REAL];
  } else {
  	remaining = 0;
  }

  timeval_from_ticks(&value->it_value, remaining);
  timeval_from_ticks(&value->it_interval, rmp->mp_interval[ITIMER_REAL]);
}

static void set_realtimer(struct mproc *rmp, const struct itimerval *value)
{
  clock_t ticks = ticks_from_timeval(&value->it_value);
  clock_t interval = ticks_from_timeval(&value->it_interval);

  if (ticks <= 0) interval = 0;

  set_alarm(rmp, ticks);
  rmp->mp_interval[ITIMER_REAL] = interval;
}

void set_alarm(struct mproc *rmp, clock_t ticks)
{
  if (ticks > 0) {
	assert(ticks <= TMRDIFF_MAX);
  	set_timer(&rmp->mp_timer, ticks, cause_sigalrm, rmp->mp_endpoint);
	rmp->mp_flags |=  ALARM_ON;
  } else if (rmp->mp_flags & ALARM_ON) {
  	cancel_timer(&rmp->mp_timer);
  	rmp->mp_flags &= ~ALARM_ON;
  }
}

static void cause_sigalrm(int arg)
{
  int proc_nr_n;
  struct mproc *rmp;

  if (pm_isokendpt(arg, &proc_nr_n) != OK) {
	printf("PM: ignoring timer for invalid endpoint %d\n", arg);
  	return;
  }

  rmp = &mproc[proc_nr_n];

  if ((rmp->mp_flags & (IN_USE | EXITING)) != IN_USE) return;
  if ((rmp->mp_flags & ALARM_ON) == 0) return;

  if (rmp->mp_interval[ITIMER_REAL] > 0)
	set_alarm(rmp, rmp->mp_interval[ITIMER_REAL]);
  else
	rmp->mp_flags &= ~ALARM_ON;

  mp = &mproc[0];

  check_sig(rmp->mp_pid, SIGALRM, FALSE);
}