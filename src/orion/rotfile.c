/*
 * Author: Ian Rose
 * Date Created: Feb 19, 2009
 *
 * Generic interface for auto-rotating files.
 *
 * Currently the rotation interval is hard-coded to be 1 hour.
 */

/* system includes */
#include <libgen.h>    /* for dirname() */
#include <stdio.h>     /* for vfprintf() */
#include <stdlib.h>    /* for malloc(), free() */
#include <string.h>    /* for strdup() */
#include <time.h>      /* for time() and time_t */
#include <sys/stat.h>  /* for S_IRWXU */

/* local includes */
#include "orion/rotfile.h"
#include "orion/fs.h"


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static int open_stream(struct orion_rotfile * restrict rf,
    const time_t * restrict clock);


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

int
orion_rotfile_close(struct orion_rotfile * restrict rf)
{
    int rv = 0;
    if (rf->fp != NULL)
        rv = fclose(rf->fp);
    free(rf->rootdir);
    free(rf->basename);
    free(rf);
    return rv;
}

int
orion_rotfile_flush(struct orion_rotfile * restrict rf)
{
    return fflush(rf->fp);
}

struct orion_rotfile *
orion_rotfile_open(const char * restrict rootdir, const char * restrict basename)
{
    struct orion_rotfile *rf = (struct orion_rotfile*)
        malloc(sizeof(struct orion_rotfile));
    if (rf == NULL) return NULL;

    /* initialize fields of orion_rotfile structure */
    rf->fp = NULL;
    rf->rootdir = strdup(rootdir);
    rf->basename = strdup(basename);

    if ((rf->rootdir == NULL) || (rf->basename == NULL)) {
        if (rf->rootdir != NULL) free(rf->rootdir);
        if (rf->basename != NULL) free(rf->basename);
        free(rf);
        return NULL;
    }

    return rf;
}

int
orion_rotfile_printf(struct orion_rotfile * restrict rf,
    const time_t * restrict clock, const char * restrict format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    int n = orion_rotfile_vprintf(rf, clock, format, argptr);
    va_end(argptr);
    return n;
}

int orion_rotfile_vprintf(struct orion_rotfile * restrict rf,
    const time_t * restrict clock, const char * restrict format, va_list ap)
{
    if (clock == NULL) {
        time_t t = time(NULL);
        clock = &t;
    }

    /* does the rotfile currently point to a real file on disk? */
    if (rf->fp == NULL) {
        if (open_stream(rf, clock) == -1)
            return -1;
    } else {
        /* check if (real) file needs to be rotated */
        struct tm now;
        localtime_r(clock, &now);

        if ((now.tm_year > rf->opened.tm_year) ||
            (now.tm_mon > rf->opened.tm_mon) ||
            (now.tm_mday > rf->opened.tm_mday) ||
            (now.tm_hour > rf->opened.tm_hour)) {
            /* time to change the rotfilefile */
            open_stream(rf, clock);
        }
    }

    return vfprintf(rf->fp, format, ap);
}

/********************/
/*  STATIC METHODS  */
/********************/

static int
open_stream(struct orion_rotfile * restrict rf, const time_t * restrict clock)
{
    if (rf->fp != NULL) {
        fflush(rf->fp);
        fclose(rf->fp);
    }

    localtime_r(clock, &rf->opened);
    
    char *path;
    if (asprintf(&path, "%s/%04d/%02d/%02d/%02d-%s", rf->rootdir,
            rf->opened.tm_year + 1900, rf->opened.tm_mon + 1,
            rf->opened.tm_mday, rf->opened.tm_hour, rf->basename) == -1)
        return -1;

    /* create directory path (if needed) */
    if (orion_fs_mkdirs(dirname(path), S_IRWXU) == -1) {
        free(path);
        return -1;
    }

    rf->fp = fopen(path, "a");
    free(path);
    return (rf->fp == NULL) ? -1 : 0;
}
