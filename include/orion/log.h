/*
 * Author: Ian Rose
 * Date Created: Feb 10, 2009
 *
 * Logging functions.
 */

#ifndef _ORION_LOG_H_
#define _ORION_LOG_H_

/* system includes */
#include <errno.h>   /* for errno */
#include <libgen.h>  /* for basename() */
#include <stdarg.h>  /* for va_list */
#include <stdio.h>   /* for FILE, strerror() */

#ifdef __cplusplus
extern "C" {
#endif 


/**********************/
/*  ENUM DEFINITIONS  */
/**********************/

/* for convenience, these match the levels in python logging module */
enum orion_log_level {
    ORION_LOG_DEBUG=10,
    ORION_LOG_INFO=20,
    ORION_LOG_WARNING=30,
    ORION_LOG_ERROR=40,
    ORION_LOG_CRITICAL=50
};


/************/
/*  MACROS  */
/************/

/*
 * 'debug' level can be used for pretty much anything, but it still shouldn't be
 *     incredibly verbose, otherwise enabling debug output is pretty useless.
 *
 * 'info' level can be used for any non-exceptional events that are relatively
 *     rare, such that the overall amount of logging output is kept low.  This
 *     is a good level for "setup" type information, such as configuration
 *     parameters, since this kind of code is typically only executed once (in
 *     the beginning).
 *
 * 'warning' level should be used when something looks wrong, but its not a
 *     definitive error; a good use of this is whenever something looks wrong in
 *     a captured packet.
 *
 * 'error' level should be used only for errors -by the application-, such as
 *     malloc failures, invalid configuration file entries, or RPC errors;
 *     errors in captured packets should always use warning-level, not
 *     error-level.
 *
 * 'critical' level should be used only for static errors, such as programming
 *     errors.
 *
 * orion_log_func() logs (at info level) the name of the currently executing
 *     function
 *
 * orion_log_errno() and orion_log_errnof() log (at error level) an error
 *     message based on the current value of the errno variable; the difference
 *     is just that orion_log_errno() takes only a single (string) argument
 *     whereas orion_log_errnof() accept printf-style varargs.
 */
#define orion_log_debug(...) orion_log_printf(ORION_LOG_DEBUG, basename(__FILE__), __VA_ARGS__)
#define orion_log_info(...)  orion_log_printf(ORION_LOG_INFO,  basename(__FILE__), __VA_ARGS__)
#define orion_log_warn(...)  orion_log_printf(ORION_LOG_WARNING,  basename(__FILE__), __VA_ARGS__)
#define orion_log_err(...)   orion_log_printf(ORION_LOG_ERROR, basename(__FILE__), __VA_ARGS__)
#define orion_log_crit(...)  orion_log_printf(ORION_LOG_CRITICAL,  basename(__FILE__), __VA_ARGS__)
#define orion_log_func()     orion_log_info("%s()", __func__)

#define orion_log_errno(s)   orion_log_printf(ORION_LOG_ERROR, basename(__FILE__), \
        "%s failed at line %d: %s", s, __LINE__, strerror(errno))

#define orion_log_errnof(fmt, ...)   orion_log_printf(ORION_LOG_ERROR, basename(__FILE__), \
        fmt " failed at line %d: %s",  __VA_ARGS__, __LINE__, strerror(errno))

#define orion_log_debug_errno(s)   orion_log_printf(ORION_LOG_DEBUG, basename(__FILE__), \
        "%s failed at line %d: %s", s, __LINE__, strerror(errno))

#define orion_log_debug_errnof(fmt, ...)   orion_log_printf(ORION_LOG_DEBUG, basename(__FILE__), \
        fmt " failed at line %d: %s",  __VA_ARGS__, __LINE__, strerror(errno))

#define orion_log_info_errno(s)   orion_log_printf(ORION_LOG_INFO, basename(__FILE__), \
        "%s failed at line %d: %s", s, __LINE__, strerror(errno))

#define orion_log_info_errnof(fmt, ...)   orion_log_printf(ORION_LOG_INFO, basename(__FILE__), \
        fmt " failed at line %d: %s",  __VA_ARGS__, __LINE__, strerror(errno))

#define orion_log_warn_errno(s)   orion_log_printf(ORION_LOG_WARNING, basename(__FILE__), \
        "%s failed at line %d: %s", s, __LINE__, strerror(errno))

#define orion_log_warn_errnof(fmt, ...)   orion_log_printf(ORION_LOG_WARNING, basename(__FILE__), \
        fmt " failed at line %d: %s",  __VA_ARGS__, __LINE__, strerror(errno))

#define orion_log_crit_errno(s)   orion_log_printf(ORION_LOG_CRITICAL, basename(__FILE__), \
        "%s failed at line %d: %s", s, __LINE__, strerror(errno))

#define orion_log_crit_errnof(fmt, ...)   orion_log_printf(ORION_LOG_CRITICAL, basename(__FILE__), \
        fmt " failed at line %d: %s",  __VA_ARGS__, __LINE__, strerror(errno))


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int orion_log_close(void);

int orion_log_flush(void);

int orion_log_fopen(FILE *stream);

inline enum orion_log_level orion_log_get_level(void);

const char *orion_log_level_desc(enum orion_log_level lvl);

enum orion_log_level orion_log_lookup_level(const char * restrict desc);

int orion_log_open(const char * restrict rootdir,
    const char * restrict basename);

int orion_log_printf(enum orion_log_level lvl, const char * restrict filename,
    const char * restrict format, ...);

int orion_log_raw(const char * restrict format, ...);

inline void orion_log_set_level(enum orion_log_level lvl);

int orion_log_vprintf(enum orion_log_level lvl, const char * restrict filename,
    const char * restrict format, va_list ap);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ORION_LOG_H_ */
