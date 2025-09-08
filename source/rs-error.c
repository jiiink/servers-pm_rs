/*
 * Changes:
 *   Mar 07, 2010:  Created  (Cristiano Giuffrida)
 */

#include "inc.h"

/* A single error entry. */
typedef struct {
    int errnum;
    const char* errstr; /* Made const char* for reliability */
} ErrorEntry;

/* Initialization errors. */
static ErrorEntry init_errlist[] = {
  { ENOSYS,     "service does not support the requested initialization type"  },
  { ERESTART,     "service requested an initialization reset"  }
};
static const int init_nerr = __arraycount(init_errlist);

/* Live update errors. */
static ErrorEntry lu_errlist[] = {
  { ENOSYS,     "service does not support live update"                        },
  { EINVAL,     "service does not support the required state"                 },
  { EBUSY,      "service is not able to prepare for the update now"           },
  { EGENERIC,   "generic error occurred while preparing for the update"       }
};
static const int lu_nerr = __arraycount(lu_errlist);

/*===========================================================================*
 *				  rs_strerror				     *
 *===========================================================================*/
static const char * rs_strerror(int errnum, const ErrorEntry *errlist, int nerr)
{
  int i;

  for(i=0; i < nerr; i++) {
      if(errnum == errlist[i].errnum)
          return errlist[i].errstr;
  }

  /* If not found in custom list, return system error string. */
  return strerror(-errnum);
}

/*===========================================================================*
 *				  init_strerror				     *
 *===========================================================================*/
const char * init_strerror(int errnum)
{
  return rs_strerror(errnum, init_errlist, init_nerr);
}

/*===========================================================================*
 *				   lu_strerror				     *
 *===========================================================================*/
const char * lu_strerror(int errnum)
{
  return rs_strerror(errnum, lu_errlist, lu_nerr);
}