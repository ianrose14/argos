/*
 * Author: Ian Rose
 * Date Created: Feb 19, 2009
 *
 * Generic interface for auto-rotating files.
 */

#ifndef _ORION_ROTFILE_H_
#define _ORION_ROTFILE_H_

#include <stdarg.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


/************************/
/*  STRUCT DEFINITIONS  */
/************************/

struct orion_rotfile {
    FILE *fp;
    struct tm opened;  /* when the current file was opened */
    char *rootdir, *basename;
    short locked;
};


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int orion_rotfile_close(struct orion_rotfile * restrict rf);

int orion_rotfile_flush(struct orion_rotfile * restrict rf);

struct orion_rotfile *orion_rotfile_open(const char * restrict rootdir,
    const char * restrict basename);

int orion_rotfile_printf(struct orion_rotfile * restrict rf,
    const time_t * restrict clock, const char * restrict format, ...);

int orion_rotfile_vprintf(struct orion_rotfile * restrict rf,
    const time_t * restrict clock, const char * restrict format, va_list ap);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ORION_ROTFILE_H_ */
