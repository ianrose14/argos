/*
 * Author: Ian Rose
 * Date Created: Feb 6, 2009
 *
 * Functions for handling configuration-file parsing.
 */

/* system includes */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* local includes */
#include "orion/config.h"
#include "orion/hash.h"


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void strip_whitespace(char **cptr);


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

/* Deallocate an orion_config_file struct. */
int
orion_config_close(struct orion_config_file *conf)
{
    struct orion_config_file *entry;
    HASH_FREE_ALL(conf, entry);
    return 0;
}

u_char
orion_config_get_bool(const struct orion_config_file * restrict conf,
    const char * restrict key, u_char defaultval)
{
    const char *val = orion_config_get_str(conf, key, NULL);
    if (val == NULL) {
        return defaultval;
    } else if (orion_config_trueval(val)) {
        return 1;
    } else if (orion_config_falseval(val)) {
        return 0;
    } else {
        errno = EINVAL;
        return defaultval;
    }
}

double
orion_config_get_double(const struct orion_config_file * restrict conf,
    const char * restrict key, double defaultval)
{
    const struct orion_config_file *entry = NULL;
    HASH_FIND_STR(conf, key, entry);
    if (entry != NULL) {
        char *cptr = NULL;
        double rv = strtod(entry->value, &cptr);

        /*
         * this is the check for "the entire string was valid" given in
         * 'man 3 strtol'
         */
        if ((entry->value[0] != '\0') && (cptr[0] == '\0')) {
            return rv;
        } else {
            errno = EINVAL;
            return defaultval;
        }
    }

    /* key not present */
    errno = ENOENT;
    return defaultval;
}

int
orion_config_get_int(const struct orion_config_file * restrict conf,
    const char * restrict key, int defaultval)
{
    const struct orion_config_file *entry = NULL;
    HASH_FIND_STR(conf, key, entry);
    if (entry != NULL) {
        char *cptr = NULL;
        int rv = (int)strtol(entry->value, &cptr, 10);

        /*
         * this is the check for "the entire string was valid" given in
         * 'man 3 strtol'
         */
        if ((entry->value[0] != '\0') && (cptr[0] == '\0')) {
            return rv;
        } else {
            errno = EINVAL;
            return defaultval;
        }
    }

    /* key not present */
    errno = ENOENT;
    return defaultval;
}

long long
orion_config_get_longlong(const struct orion_config_file * restrict conf,
    const char * restrict key, long long defaultval)
{
    const struct orion_config_file *entry = NULL;
    HASH_FIND_STR(conf, key, entry);
    if (entry != NULL) {
        char *cptr = NULL;
        long long rv = strtoll(entry->value, &cptr, 10);

        /*
         * this is the check for "the entire string was valid" given in
         * 'man 3 strtol'
         */
        if ((entry->value[0] != '\0') && (cptr[0] == '\0')) {
            return rv;
        } else {
            errno = EINVAL;
            return defaultval;
        }
    }

    /* key not present */
    errno = ENOENT;
    return defaultval;
}

const char *
orion_config_get_str(const struct orion_config_file * restrict conf,
    const char * restrict key, const char *defaultval)
{
    /* have to declare this static so that it will exist after returning */
    static const struct orion_config_file *entry = NULL;
    HASH_FIND_STR(conf, key, entry);
    if (entry == NULL) {
        /* key not present */
        errno = ENOENT;
        return defaultval;
    } else {
        return entry->value;
    }
}

int
orion_config_haskey(const struct orion_config_file * restrict conf,
    const char * restrict key)
{
    const struct orion_config_file *entry = NULL;
    HASH_FIND_STR(conf, key, entry);
    return (entry != NULL);
}

/*
 * Create and initialize a new orion_config_file struct.  Returns NULL and sets
 * errno on any failure.
 */
struct orion_config_file *
orion_config_open(const char * restrict filename)
{
    FILE *stream = fopen(filename, "r");
    if (stream == NULL) return NULL;

    struct orion_config_file *conf = NULL;
    char cbuf[1500];

    while (1) {
        if (fgets(cbuf, sizeof(cbuf), stream) == NULL) {
            if (feof(stream))
                return conf;
            else
                goto fail;
        }

        char *cptr = cbuf;
        strip_whitespace(&cptr);
        
        int len = strlen(cptr);
        if (len == 0) continue;  /* line is just whitespace */
        if (cptr[0] == '#') continue;  /* line is commented out */

        char *sep = strchr(cptr, '=');
        if (sep == NULL) {  /* malformed line */
            errno = EFTYPE;
            goto fail;
        }
        sep[0] = '\0';

        /* parse out the parameter key */
        strip_whitespace(&cptr);
        if (strlen(cptr) == 0) {
            errno = EFTYPE;
            goto fail;
        }

        struct orion_config_file* entry =
            (struct orion_config_file*)malloc(sizeof(struct orion_config_file));
        if (entry == NULL)
            goto fail;
        strlcpy(entry->key, cptr, sizeof(entry->key));
        
        /* parse out the parameter value */
        cptr = sep + 1;
        strip_whitespace(&cptr);

        /* if value is surrounded by quotes, strip them */
        len = strlen(cptr);
        if (((cptr[0] == '"') && (cptr[len-1] == '"')) ||
            ((cptr[0] == '\'') && (cptr[len-1] == '\''))) {
            cptr[len-1] = '\0';  /* set this before advancing cptr */
            cptr += 1;
        }

        /* note: do NOT strip whitespace after stripping quotes */
        strlcpy(entry->value, cptr, sizeof(entry->value));
        HASH_ADD_STR(conf, key, entry);
    }

    assert(0  /* should never get here */);

 fail:
    orion_config_close(conf);
    return NULL;
}


/********************/
/*  STATIC METHODS  */
/********************/

static void
strip_whitespace(char **cptr)
{
    char *ptr;

    for (ptr = *cptr ; (ptr != '\0') && isspace(ptr[0]); ptr++);
    for (int i = strlen(ptr) - 1; (i >= 0) && isspace(ptr[i]); i--)
        ptr[i] = '\0';

    *cptr = ptr;
}
