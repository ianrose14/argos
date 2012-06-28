/*
 * Author: Ian Rose
 * Date Created: Feb 24, 2009
 *
 * Logging functions.
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* local includes */
#include "orion/log.h"
#include "orion/rotfile.h"


/**********************/
/*  STATIC VARIABLES  */
/**********************/

static enum log_state { LOG_STATE_CLOSED, LOG_STATE_FILE, LOG_STATE_STREAM } log_state =
    LOG_STATE_CLOSED;
static enum orion_log_level log_thresh = ORION_LOG_INFO;
static struct orion_rotfile *log_rotfile = NULL;
static FILE *log_stream = NULL;

/* log level descriptions */
static char *debug_desc = "DEBUG";
static char *info_desc = "INFO";
static char *warning_desc = "WARN";
static char *error_desc = "ERR";
static char *critical_desc = "CRIT";


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

int
orion_log_close()
{
    int n = 0;
    switch (log_state) {
    case LOG_STATE_CLOSED:
        errno = EBADF;
        return -1;
    case LOG_STATE_FILE:
        n = orion_rotfile_close(log_rotfile);
        log_rotfile = NULL;
        break;
    case LOG_STATE_STREAM:
        /* note: do NOT close the stream itself, but flush it */
        n = fflush(log_stream);
        log_stream = NULL;
        break; 
    default:
        assert(0  /* invalid log_state */);
    }

    int myerrno = 0;
    if (n != 0) myerrno = errno;

    log_state = LOG_STATE_CLOSED;
    errno = myerrno;
    return n;
}

int
orion_log_flush(void)
{
    int n = 0;
    switch (log_state) {
    case LOG_STATE_CLOSED:
        errno = EBADF;
        return -1;
    case LOG_STATE_FILE:
        n = orion_rotfile_flush(log_rotfile);
        break;
    case LOG_STATE_STREAM:
        n = fflush(log_stream);
        break;
    default:
        assert(0);  /* programming error */
    }

    if (n == -1) return -1;

    return 0;
}

int
orion_log_fopen(FILE *stream)
{
    if (log_state != LOG_STATE_CLOSED) {
        /*
         * if the logfile is already open, then we close it here, although this
         * is bad programming style because errors from close() are ignored.
         */
        orion_log_close();
    }
    log_stream = stream;
    log_state = LOG_STATE_STREAM;
    return 0;
}

inline enum orion_log_level
orion_log_get_level()
{
    return log_thresh;
}

const char *
orion_log_level_desc(enum orion_log_level lvl)
{
    switch (lvl) {
    case ORION_LOG_DEBUG:
        return debug_desc;
    case ORION_LOG_INFO:
        return info_desc;
    case ORION_LOG_WARNING:
        return warning_desc;
    case ORION_LOG_ERROR:
        return error_desc;
    case ORION_LOG_CRITICAL:
        return critical_desc;
    default:
        errno = EINVAL;
        return NULL;
    }
}

enum orion_log_level
orion_log_lookup_level(const char * restrict desc)
{
    if (strcmp(desc, debug_desc) == 0)
        return ORION_LOG_DEBUG;
    if (strcmp(desc, info_desc) == 0)
        return ORION_LOG_INFO;
    if (strcmp(desc, warning_desc) == 0)
        return ORION_LOG_WARNING;
    if (strcmp(desc, error_desc) == 0)
        return ORION_LOG_ERROR;
    if (strcmp(desc, critical_desc) == 0)
        return ORION_LOG_CRITICAL;
    /* else */
    errno = EINVAL;
    return -1;
}

int
orion_log_open(const char * restrict rootdir, const char * restrict basename)
{
    if (log_state != LOG_STATE_CLOSED) {
        /*
         * if the logfile is already open, then we close it here, although this
         * is bad programming style because errors from close() are ignored.
         */
        orion_log_close();
    }

    log_rotfile = orion_rotfile_open(rootdir, basename);
    log_state = LOG_STATE_FILE;
    return log_rotfile == NULL ? -1 : 0;
}

int
orion_log_printf(enum orion_log_level lvl, const char * restrict filename,
    const char * restrict format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = orion_log_vprintf(lvl, filename, format, ap);
    va_end(ap);
    return n;
}

int
orion_log_raw(const char * restrict format, ...)
{
    va_list ap;
    va_start(ap, format);

    struct timeval now;
    gettimeofday(&now, NULL);
    
    int len = 0;
    switch (log_state) {
    case LOG_STATE_CLOSED:
        errno = EBADF;
        len = -1;
        break;
    case LOG_STATE_FILE:
        len = orion_rotfile_vprintf(log_rotfile, &now.tv_sec, format, ap);
        break;
    case LOG_STATE_STREAM:
        len = vfprintf(log_stream, format, ap);
        break;
    default:
        assert(0);  /* programming error */
    }

    va_end(ap);
    return len;
}

inline void
orion_log_set_level(enum orion_log_level lvl)
{
    log_thresh = lvl;
}

int
orion_log_vprintf(enum orion_log_level lvl, const char * restrict filename,
    const char * restrict format, va_list ap)
{
    const char *desc = orion_log_level_desc(lvl);
    if (desc == NULL) {  /* invalid lvl */
        errno = EINVAL;
        return -1;
    }
    if (lvl < log_thresh)
        return 0;  /* below threshold for printing */

    /*
     * format of string written by ctime_r (all fields fixed width):
     *   Thu Nov 24 18:22:48 1986\n\0
     * the length (26) should be a macro in time.h :(
     */
    struct timeval now;
    gettimeofday(&now, NULL);
    uint32_t msec = now.tv_usec/1000;

    char datebuf[26];
    ctime_r(&now.tv_sec, datebuf);
    datebuf[19] = '\0';  /* truncate off the " 1986\n" at the end */
    char *dateptr = datebuf + 4;  /* skip the "Thu " at the front */
    
    /* args: date-desc, time-milliseconds, filename, log-level-desc */
    const char *prefix = "%s.%03d %-15s %-5s ";

    int len = 0, n;
    switch (log_state) {
    case LOG_STATE_CLOSED:
        errno = EBADF;
        len = -1;
        break;
    case LOG_STATE_FILE:
        /*
         * by providing the same time (now.tv_sec) to each call to rotfile print
         * call, we ensure that the file will not rotate in the middle of these
         * calls (leading to a line that spans 2 files)
         */
        len = orion_rotfile_printf(log_rotfile, &now.tv_sec, prefix, dateptr, msec,
            basename(filename), desc);
        if (len == -1) return -1;
        n = orion_rotfile_vprintf(log_rotfile, &now.tv_sec, format, ap);
        if (n == -1) return -1;
        len += n;
        n = orion_rotfile_printf(log_rotfile, &now.tv_sec, "\n");
        if (n == -1) return -1;
        len += n;
        break;
    case LOG_STATE_STREAM:
        len = fprintf(log_stream, prefix, dateptr, msec, basename(filename),
            desc);
        if (len == -1) return -1;
        n = vfprintf(log_stream, format, ap);
        if (n == -1) return -1;
        len += n;
        n = fprintf(log_stream, "\n");
        if (n == -1) return -1;
        len += n;
        break;
    default:
        assert(0);  /* programming error */
    }

    /* on log entries of level WARNING and above, we autoflush */
    if (lvl >= ORION_LOG_WARNING)
        orion_log_flush();

    return len;
}
