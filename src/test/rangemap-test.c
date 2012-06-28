/*
 * Author: Ian Rose
 * Date Created: Apr 3, 2009
 *
 * Tests rangemap.c
 */

/* system includes */
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* local includes */
#include "rangemap.h"


static void print_rmap(rangemap_t *rmap)
{
    int first = 1;
    rangemap_reset_elt(rmap);
    printf("{ ");
    if (rangemap_is_empty(rmap)) {
        printf("none");
    } else {
        while (1) {
            if (first)
                first = 0;
            else
                printf(", ");
            printf("(%u,%u)", rangemap_get_elt_start(rmap), rangemap_get_elt_length(rmap));
            if (rangemap_next_elt(rmap) == -1)
                break;
        }
    }
    printf(" }");
}


/**********/
/*  MAIN  */
/**********/

#define CHECK_COMPLETE(start, len)                             \
    printf("rangemap_contains(%u, %u) = %d\n", start, len,     \
        rangemap_contains(rmap, start, len))                   \

#define DOPUT(start, len)                                       \
    do {                                                        \
        printf("rangemap_put(%u, %u)...   rmap: ", start, len); \
        if (rangemap_put(rmap, start, len) == -1)               \
            err(1, "rangemap_put");                             \
        print_rmap(rmap);                                       \
        printf("\n");                                           \
    } while (0);                                                \


int main(int argc, char **argv)
{
    rangemap_t *rmap = rangemap_create();
    if (rmap == NULL) err(1, "rangemap_create");

    DOPUT(0, 5);
    CHECK_COMPLETE(0, 10);
    DOPUT(5, 1);
    CHECK_COMPLETE(0, 10);
    DOPUT(10, 5);
    CHECK_COMPLETE(0, 10);
    DOPUT(2, 3);
    CHECK_COMPLETE(0, 10);
    DOPUT(3, 4);
    CHECK_COMPLETE(0, 10);
    DOPUT(7, 4);
    CHECK_COMPLETE(0, 10);
    DOPUT(0, 12);
    CHECK_COMPLETE(0, 10);

    printf("---------------------------------\n");

    DOPUT(25, 5);
    CHECK_COMPLETE(20, 10);
    DOPUT(22, 3);
    CHECK_COMPLETE(22, 8);
    DOPUT(30, 2);
    CHECK_COMPLETE(22, 10);
    DOPUT(35, 1);
    CHECK_COMPLETE(22, 13);
    CHECK_COMPLETE(22, 14);
    CHECK_COMPLETE(22, 15);
    DOPUT(30, 5);
    CHECK_COMPLETE(22, 13);
    CHECK_COMPLETE(22, 14);
    CHECK_COMPLETE(22, 15);

    printf("---------------------------------\n");

    DOPUT(40, 5);
    CHECK_COMPLETE(40, 10);
    DOPUT(45, 30);
    CHECK_COMPLETE(40, 10);
    DOPUT(38, 60);
    CHECK_COMPLETE(40, 10);

    DOPUT(15, 10);
    DOPUT(30, 20);

    rangemap_destroy(rmap);
    printf("all done!\n");
    return 0;
}
