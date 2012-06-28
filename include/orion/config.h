/*
 * Author: Ian Rose
 * Date Created: Feb 6, 2009
 *
 * Functions for handling configuration-file parsing.
 */

#ifndef _ORION_CONFIG_H_
#define _ORION_CONFIG_H_

/* system includes */
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>

/* local includes */
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif


/************************/
/*  STRUCT DEFINITIONS  */
/************************/

#define ORION_CONFIG_MAX_KEYLEN 128
#define ORION_CONFIG_MAX_VALUELEN 1024

struct orion_config_file {
    UT_hash_handle hh;      /* uthash handle (required for hashing) */
    char key[ORION_CONFIG_MAX_KEYLEN];
    char value[ORION_CONFIG_MAX_VALUELEN];
};


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

#define orion_config_trueval(x)                 \
    ((strcmp((x), "1") == 0) ||                 \
        (strcasecmp((x), "yes") == 0) ||        \
        (strcasecmp((x), "true") == 0))

#define orion_config_falseval(x)                 \
    ((strcmp((x), "0") == 0) ||                  \
        (strcasecmp((x), "no") == 0) ||          \
        (strcasecmp((x), "false") == 0))

int orion_config_close(struct orion_config_file *conf);

u_char orion_config_get_bool(const struct orion_config_file * restrict conf,
    const char * restrict key, u_char defaultval);

double orion_config_get_double(const struct orion_config_file * restrict conf,
    const char * restrict key, double defaultval);

int orion_config_get_int(const struct orion_config_file * restrict conf,
    const char * restrict key, int defaultval);

long long orion_config_get_longlong(const struct orion_config_file * restrict conf,
    const char * restrict key, long long defaultval);

const char *orion_config_get_str(const struct orion_config_file * restrict conf,
    const char * restrict key, const char *defaultval);

int orion_config_haskey(const struct orion_config_file * restrict conf,
    const char * restrict name);

struct orion_config_file *orion_config_open(const char * restrict filename);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ORION_CONFIG_H_ */
