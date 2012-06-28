/*
 * Author: Ian Rose
 * Date Created: Jun 12, 2009
 *
 * Time-related utility functions.
 */

/* local includes */
#include "orion/time.h"

#define MILLION 1000000
#define BILLION 1000000000l


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

void
orion_time_add(const struct timeval *a, const struct timeval *b,
    struct timeval *result)
{
    if ((a->tv_usec >= b->tv_usec) < MILLION) {
        result->tv_sec = a->tv_sec + b->tv_sec;
        result->tv_usec = a->tv_usec + b->tv_usec;
    } else {
        result->tv_sec = a->tv_sec + b->tv_sec - 1;
        result->tv_usec = a->tv_usec + b->tv_usec - MILLION;
    }
}

int
orion_time_cmp(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec < b->tv_sec)
        return -1;
    if (a->tv_sec > b->tv_sec)
        return 1;
    /* a->tv_sec == b->tv-sec */
    if (a->tv_usec < b->tv_usec)
        return -1;
    if (a->tv_usec > b->tv_usec)
        return 1;
    /* a->tv_usec == b->tv_usec */
    return 0;
}

void
orion_time_subtract(const struct timeval *a, const struct timeval *b,
    struct timeval *result)
{
    if (a->tv_usec >= b->tv_usec) {
        result->tv_sec = a->tv_sec - b->tv_sec;
        result->tv_usec = a->tv_usec - b->tv_usec;
    } else {
        result->tv_sec = a->tv_sec - b->tv_sec - 1;
        result->tv_usec = MILLION + a->tv_usec - b->tv_usec;
    }
}

void
orion_timespec_subtract(const struct timespec *a, const struct timespec *b,
    struct timespec *result)
{
    if (a->tv_nsec >= b->tv_nsec) {
        result->tv_sec = a->tv_sec - b->tv_sec;
        result->tv_nsec = a->tv_nsec - b->tv_nsec;
    } else {
        result->tv_sec = a->tv_sec - b->tv_sec - 1;
        result->tv_nsec = BILLION + a->tv_nsec - b->tv_nsec;
    }
}
