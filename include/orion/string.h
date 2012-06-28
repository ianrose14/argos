/*
 * Author: Ian Rose
 * Date Created: Aug 20, 2009
 *
 * String-related utility functions.
 */

#ifndef _ORION_STR_H_
#define _ORION_STR_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

ssize_t orion_str_unshellify(const char *arg, char *result, size_t len);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ORION_STR_H_ */
