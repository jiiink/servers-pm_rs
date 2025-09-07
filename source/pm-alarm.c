/* This file deals with the alarm clock related system calls, eventually
 * passing off the work to the functions in timers.c and check_sig() in
 * signal.c to pass an alarm signal to a process.
 *
 * The entry points into this file are:
 *   do_itimer: perform the ITIMER system call
 *   set_alarm: tell the timer interface to start or stop a process timer
 *   check_vtimer: check if one of the virtual timers needs to be restarted
 */

#include "pm.h"
#include <signal.h>
#include <sys/time.h>
#include <minix/com.h>
#include <minix/callnr.h>
#include <assert.h>
#include "mproc.h"

#define US 1000000UL	/* shortcut for microseconds per second */
#define MAX_TIMER_VALUE LONG_MAX

/* Function prototypes */
static clock_t ticks_from_timeval(const struct timeval *tv);
static void timeval_from_ticks(struct timeval *tv, clock_t ticks);
static int is_sane_timeval(const struct timeval *tv);
static void getset_vtimer(struct mproc *mp, int nwhich, 
	const struct itimerval *value, struct itimerval *ovalue);
static void get_realtimer(const struct mproc *mp, struct itimerval *value);
static void set_realtimer(struct mproc *mp, const struct itimerval *value);
static void cause_sigalrm(int arg);
static int validate_timer_params(int which, int setval, int getval);
static int copy_timer_value(const struct itimerval *value);

/*===========================================================================*
 *				ticks_from_timeval			     *
 *===========================================================================*/
static clock_t ticks_from_timeval(const struct timeval *tv)
{
  clock_t ticks;
  unsigned long seconds_in_ticks;
  unsigned long usecs_in_ticks;

  if (tv == NULL) {
    return 0;
  }

  /* Validate input */
  if (tv->tv_sec < 0 || tv->tv_usec < 0) {
    return 0;
  }

  /* Check for overflow in seconds conversion */
  seconds_in_ticks = system_hz * (unsigned long)tv->tv_sec;
  if ((seconds_in_ticks / system_hz) != (unsigned long)tv->tv_sec) {
    return MAX_TIMER_VALUE;
  }

  /* Calculate microseconds part */
  usecs_in_ticks = (system_hz * (unsigned long)tv->tv_usec + (US - 1)) / US;
  
  /* Check for overflow in addition */
  ticks = seconds_in_ticks + usecs_in_ticks;
  if (ticks < seconds_in_ticks || ticks > MAX_TIMER_VALUE) {
    return MAX_TIMER_VALUE;
  }

  return ticks;
}

/*===========================================================================*
 *				timeval_from_ticks			     *
 *===========================================================================*/
static void timeval_from_ticks(struct timeval *tv, clock_t ticks)
{
  if (tv == NULL) {
    return;
  }

  tv->tv_sec = (long)(ticks / system_hz);
  tv->tv_usec = (long)((ticks % system_hz) * US / system_hz);
}

/*===========================================================================*
 *				is_sane_timeval				     *
 *===========================================================================*/
static int is_sane_timeval(const struct timeval *tv)
{
  if (tv == NULL) {
    return 0;
  }

  /* This imposes a reasonable time value range for setitimer. */
  return (tv->tv_sec >= 0 && tv->tv_sec <= MAX_SECS &&
          tv->tv_usec >= 0 && tv->tv_usec < US);
}

/*===========================================================================*
 *				validate_timer_params			     *
 *===========================================================================*/
static int validate_timer_params(int which, int setval, int getval)
{
  /* Validate timer type */
  if (which < 0 || which >= NR_ITIMERS) {
    return EINVAL;
  }

  /* At least one operation must be requested */
  if (!setval && !getval) {
    return EINVAL;
  }

  return OK;
}

/*===========================================================================*
 *				copy_timer_value			     *
 *===========================================================================*/
static int copy_timer_value(const struct itimerval *value)
{
  struct itimerval local_value;
  int r;

  r = sys_datacopy(who_e, m_in.m_lc_pm_itimer.value,
                   PM_PROC_NR, (vir_bytes)&local_value, 
                   (phys_bytes)sizeof(local_value));
  if (r != OK) {
    return r;
  }

  if (!is_sane_timeval(&local_value.it_value) ||
      !is_sane_timeval(&local_value.it_interval)) {
    return EINVAL;
  }

  if (value != NULL) {
    *(struct itimerval *)value = local_value;
  }

  return OK;
}

/*===========================================================================*
 *				do_itimer				     *
 *===========================================================================*/
int do_itimer(void)
{
  struct itimerval ovalue, value;
  int setval, getval;
  int r, which;

  which = m_in.m_lc_pm_itimer.which;
  setval = (m_in.m_lc_pm_itimer.value != 0);
  getval = (m_in.m_lc_pm_itimer.ovalue != 0);

  /* Validate parameters */
  r = validate_timer_params(which, setval, getval);
  if (r != OK) {
    return r;
  }

  /* Copy new timer value if setting */
  if (setval) {
    r = copy_timer_value(&value);
    if (r != OK) {
      return r;
    }
  }

  /* Process timer operation */
  switch (which) {
    case ITIMER_REAL:
      if (getval) {
        get_realtimer(mp, &ovalue);
      }
      if (setval) {
        set_realtimer(mp, &value);
      }
      break;

    case ITIMER_VIRTUAL:
    case ITIMER_PROF:
      getset_vtimer(mp, which, setval ? &value : NULL,
                    getval ? &ovalue : NULL);
      break;

    default:
      panic("invalid timer type: %d", which);
  }

  /* Copy old timer value back if requested */
  if (getval) {
    r = sys_datacopy(PM_PROC_NR, (vir_bytes)&ovalue,
                     who_e, m_in.m_lc_pm_itimer.ovalue,
                     (phys_bytes)sizeof(ovalue));
    if (r != OK) {
      return r;
    }
  }

  return OK;
}

/*===========================================================================*
 *				getset_vtimer				     *
 *===========================================================================*/
static void getset_vtimer(struct mproc *rmp, int which, 
                          const struct itimerval *value, 
                          struct itimerval *ovalue)
{
  clock_t newticks, oldticks;
  clock_t *nptr = NULL;
  clock_t *optr = NULL;
  int r, num;

  if (rmp == NULL) {
    return;
  }

  /* Setup output pointer if old value requested */
  if (ovalue != NULL) {
    optr = &oldticks;
    timeval_from_ticks(&ovalue->it_interval, rmp->mp_interval[which]);
  }

  /* Setup new timer if value provided */
  if (value != NULL) {
    newticks = ticks_from_timeval(&value->it_value);
    nptr = &newticks;

    /* Clear interval if no timer set */
    if (newticks <= 0) {
      rmp->mp_interval[which] = 0;
    } else {
      rmp->mp_interval[which] = ticks_from_timeval(&value->it_interval);
    }
  }

  /* Determine kernel timer number */
  switch (which) {
    case ITIMER_VIRTUAL: 
      num = VT_VIRTUAL; 
      break;
    case ITIMER_PROF:    
      num = VT_PROF;    
      break;
    default:             
      panic("invalid vtimer type: %d", which);
  }

  /* Make kernel call */
  r = sys_vtimer(rmp->mp_endpoint, num, nptr, optr);
  if (r != OK) {
    panic("sys_vtimer failed: %d", r);
  }

  /* Process old value if requested */
  if (ovalue != NULL) {
    if (oldticks <= 0) {
      oldticks = rmp->mp_interval[which];
    }
    timeval_from_ticks(&ovalue->it_value, oldticks);
  }
}

/*===========================================================================*
 *				check_vtimer				     *
 *===========================================================================*/
void check_vtimer(int proc_nr, int sig)
{
  struct mproc *rmp;
  int which, num;

  if (proc_nr < 0 || proc_nr >= NR_PROCS) {
    return;
  }

  rmp = &mproc[proc_nr];

  /* Map signal to timer type */
  switch (sig) {
    case SIGVTALRM: 
      which = ITIMER_VIRTUAL; 
      num = VT_VIRTUAL; 
      break;
    case SIGPROF:   
      which = ITIMER_PROF;    
      num = VT_PROF;    
      break;
    default: 
      panic("invalid vtimer signal: %d", sig);
  }

  /* Reset timer if interval is set */
  if (rmp->mp_interval[which] > 0) {
    sys_vtimer(rmp->mp_endpoint, num, &rmp->mp_interval[which], NULL);
  }
}

/*===========================================================================*
 *				get_realtimer				     *
 *===========================================================================*/
static void get_realtimer(const struct mproc *rmp, struct itimerval *value)
{
  clock_t exptime, uptime, remaining;

  if (rmp == NULL || value == NULL) {
    return;
  }

  /* Calculate remaining time */
  if (rmp->mp_flags & ALARM_ON) {
    uptime = getticks();
    exptime = tmr_exp_time(&rmp->mp_timer);
    remaining = exptime - uptime;

    /* Use interval if timer already expired */
    if (remaining <= 0) {
      remaining = rmp->mp_interval[ITIMER_REAL];
    }
  } else {
    remaining = 0;
  }

  /* Convert to timeval structures */
  timeval_from_ticks(&value->it_value, remaining);
  timeval_from_ticks(&value->it_interval, rmp->mp_interval[ITIMER_REAL]);
}

/*===========================================================================*
 *				set_realtimer				     *
 *===========================================================================*/
static void set_realtimer(struct mproc *rmp, const struct itimerval *value)
{
  clock_t ticks, interval;

  if (rmp == NULL || value == NULL) {
    return;
  }

  /* Convert timeval to ticks */
  ticks = ticks_from_timeval(&value->it_value);
  interval = ticks_from_timeval(&value->it_interval);

  /* Clear interval if no timer */
  if (ticks <= 0) {
    interval = 0;
  }

  /* Apply values */
  set_alarm(rmp, ticks);
  rmp->mp_interval[ITIMER_REAL] = interval;
}

/*===========================================================================*
 *				set_alarm				     *
 *===========================================================================*/
void set_alarm(struct mproc *rmp, clock_t ticks)
{
  if (rmp == NULL) {
    return;
  }

  if (ticks > 0) {
    assert(ticks <= TMRDIFF_MAX);
    set_timer(&rmp->mp_timer, ticks, cause_sigalrm, rmp->mp_endpoint);
    rmp->mp_flags |= ALARM_ON;
  } else if (rmp->mp_flags & ALARM_ON) {
    cancel_timer(&rmp->mp_timer);
    rmp->mp_flags &= ~ALARM_ON;
  }
}

/*===========================================================================*
 *				cause_sigalrm				     *
 *===========================================================================*/
static void cause_sigalrm(int arg)
{
  int proc_nr_n;
  struct mproc *rmp;

  /* Validate endpoint */
  if (pm_isokendpt(arg, &proc_nr_n) != OK) {
    printf("PM: ignoring timer for invalid endpoint %d\n", arg);
    return;
  }

  rmp = &mproc[proc_nr_n];

  /* Check process state */
  if ((rmp->mp_flags & (IN_USE | EXITING)) != IN_USE) {
    return;
  }
  if ((rmp->mp_flags & ALARM_ON) == 0) {
    return;
  }

  /* Reset timer or clear flag */
  if (rmp->mp_interval[ITIMER_REAL] > 0) {
    set_alarm(rmp, rmp->mp_interval[ITIMER_REAL]);
  } else {
    rmp->mp_flags &= ~ALARM_ON;
  }

  /* Send signal */
  mp = &mproc[0];
  check_sig(rmp->mp_pid, SIGALRM, FALSE);
}