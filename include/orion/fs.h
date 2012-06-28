/*
 * Author: Ian Rose
 * Date Created: Jan 22, 2009
 *
 * Filesystem-related utility functions.
 */

#ifndef _ORION_FS_H_
#define _ORION_FS_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int orion_fs_mkdirs(const char * restrict path, mode_t mode);
int orion_fs_open_pidfile(const char * restrict pidfile);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ORION_FS_H_ */
