/*
 * Author: Ian Rose
 * Date Created: Feb 9, 2009
 *
 * Additions to uthash.
 */

#ifndef _ARGOS_HASH_H_
#define _ARGOS_HASH_H_

/* system includes */
#include <stdlib.h>   /* for malloc() */


/************/
/*  MACROS  */
/************/

#define HASH_FREE_ALL(head,ptr)                 \
    while (head) {                              \
        ptr = head;                             \
        HASH_DEL(head,ptr);                     \
        free(ptr);                              \
    }

#define HASH_FIND_OR_CREATE(hh,head,keyptr,keylen_in,fieldname,type,out) \
    do {                                                                \
        out = NULL;                                                     \
        HASH_FIND(hh, head, keyptr, keylen_in, out);                    \
        if (out == NULL) {                                              \
            out = (type*)malloc(sizeof(type));                          \
            if (out != NULL) {                                          \
                (void) memset(out, 0, sizeof(type));                    \
                (void) memcpy(&(out->fieldname), keyptr, keylen_in);    \
                HASH_ADD(hh, head, fieldname, keylen_in, out);          \
            }                                                           \
        }                                                               \
    } while (0)

#endif  /* #ifndef _ARGOS_HASH_H_ */
