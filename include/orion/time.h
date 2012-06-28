/*
 * Author: Ian Rose
 * Date Created: Jun 12, 2009
 *
 * Time-related utility functions.
 */

#ifndef _ORION_TIME_H_
#define _ORION_TIME_H_

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

void orion_time_add(const struct timeval *a, const struct timeval *b,
    struct timeval *result);

int orion_time_cmp(const struct timeval *a, const struct timeval *b);

void orion_time_subtract(const struct timeval *a, const struct timeval *b,
    struct timeval *result);

void orion_timespec_subtract(const struct timespec *a, const struct timespec *b,
    struct timespec *result);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _ORION_TIME_H_ */
