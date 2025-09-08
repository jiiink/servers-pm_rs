#include "inc.h"

struct errentry {
    int errnum;
    char* errstr;
};

static const struct errentry init_errlist[] = {
    { ENOSYS, "service does not support the requested initialization type" },
    { ERESTART, "service requested an initialization reset" }
};
static const int init_nerr = sizeof(init_errlist) / sizeof(init_errlist[0]);

static const struct errentry lu_errlist[] = {
    { ENOSYS, "service does not support live update" },
    { EINVAL, "service does not support the required state" },
    { EBUSY, "service is not able to prepare for the update now" },
    { EGENERIC, "generic error occurred while preparing for the update" }
};
static const int lu_nerr = sizeof(lu_errlist) / sizeof(lu_errlist[0]);

static char *rs_strerror(int errnum, const struct errentry *errlist, int nerr)
{
    for (int i = 0; i < nerr; i++) {
        if (errnum == errlist[i].errnum) {
            return errlist[i].errstr;
        }
    }
    return strerror(-errnum);
}

char *init_strerror(int errnum)
{
    return rs_strerror(errnum, init_errlist, init_nerr);
}

char *lu_strerror(int errnum)
{
    return rs_strerror(errnum, lu_errlist, lu_nerr);
}