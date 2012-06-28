/*
 * Author: Ian Rose
 * Date Created: Apr 3, 2009
 *
 * Tests vector.c
 */

/* system includes */
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* local includes */
#include "vector.h"


/**********/
/*  MAIN  */
/**********/

int main(int argc, char **argv)
{
    vector_t *vec = vector_create(sizeof(int), 5, 0, 5);
    if (vec == NULL) err(1, "vector_create");

    int i, v;

    for (i=0; i < 5; i++) {
        v = 10 + i;
        printf("setting vec[%d] = %d\n", i, v);
        if (vector_set(vec, i, &v) != 0)
            err(1, "vector_set");
    }

    for (i=0; i < 5; i++) {
        printf("getting vec[%d]\n", i);
        vector_get(vec, i, &v);
        printf("vec[%d] = %d\n", i, v);
    }

    i = 6;
    v = 22;
    printf("setting vec[%d] = %d\n", i, v);
    if (vector_set(vec, i, &v) != 0)
        err(1, "vector_set");
    v = 0;
    printf("getting vec[%d]\n", i);
    vector_get(vec, i, &v);
    printf("vec[%d] = %d\n", i, v);

    i = 100;
    v = 33;
    printf("setting vec[%d] = %d\n", i, v);
    if (vector_set(vec, i, &v) != 0)
        err(1, "vector_set");
    v = 0;
    printf("getting vec[%d]\n", i);
    vector_get(vec, i, &v);
    printf("vec[%d] = %d\n", i, v);

    i = 1000*1000*1000;
    v = 44;
    printf("setting vec[%d] = %d\n", i, v);
    int rv = vector_set(vec, i, &v);
    if (rv == -1) {
        if (errno == ENOMEM) {
            printf("failed due to ENOMEM, as expected\n");
        } else {
            err(1, "vector_set");
        }
    } else {
        printf("warning: vector_set unexpectedly worked\n");
        v = 0;
        printf("getting vec[%d]\n", i);
        vector_get(vec, i, &v);
        printf("vec[%d] = %d\n", i, v);
    }

    /* should cause abort() */
    i = 1000*1000*1000 + 500*1000;
    printf("getting vec[%d] (should abort)\n", i);
    vector_get(vec, i, &v);
    printf("vec[%d] = %d\n", i, v);
}
