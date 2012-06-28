/*
 * Author: Ian Rose
 * Date Created: Aug 20, 2009
 *
 * String-related utility functions.
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/* local includes */
#include "orion/string.h"


/**********************/
/*  EXTERNAL METHODS  */
/**********************/


ssize_t
orion_str_unshellify(const char *arg, char *result, size_t len)
{
    if (len == 0) {
        errno = EINVAL;
        return -1;
    }

    char *cmd;
    if (asprintf(&cmd, "echo %s", arg) == -1)
        return -1;

    FILE *proc = popen(cmd, "r");
    if (proc == NULL) goto fail;

    size_t readlen = 0;
    while (readlen < (len-1)) {
        size_t l = fread(result + readlen, 1, (len-1) - readlen, proc);
        if (l == 0) {
            if (ferror(proc)) goto fail;
            break;
        }
        readlen += l;
    }

    result[readlen-1] = '\0';

    /* save EOF status because feof can't be called after pclose() */
    int eof = feof(proc);  

    if (pclose(proc) != 0) {
        errno = EINVAL;  /* probably a bad string was passed */
        return -1;
    }

    if (eof) {
        return readlen;
    } else {
        /* looks like result buffer is not big enough */
        printf("readlen=%d\n", readlen);
        printf("len=%d\n", len);
        printf("ferr = %d\n", ferror(proc));
        assert(readlen == (len-1));
        errno = ENOBUFS;
        return -1;
    }

 fail:
    if (proc != NULL) pclose(proc);
    free(cmd);
    return -1;
}
