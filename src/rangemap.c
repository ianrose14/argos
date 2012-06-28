/*
 * Author: Ian Rose
 * Date Created: Apr 3, 2009
 *
 * A data structure for keeping track of ranges of numbers.  For example, you
 * can store "1-10, 10-15, 18-20, and 100-150" and then later you can walk
 * through the net results (which are "1-15, 18-20 and 100-150").
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

/* local includes */
#include "rangemap.h"


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void compact_list(rangemap_t *rmap);
static int compare_elts(const struct rangemap_elt *elt, uint32_t start, uint32_t length);
static void merge_elts(struct rangemap_elt *elt, uint32_t start, uint32_t length);


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

int
rangemap_contains(const rangemap_t *rmap, uint32_t start, uint32_t len)
{
    struct rangemap_elt *elt;
    LIST_FOREACH(elt, &rmap->list, next) {
        if ((start + len) <= (elt->start + elt->length)) {
            if (start >= elt->start) {
                return 1;
            } else {
                return 0;
            }
        }
    }

    return 0;
}

rangemap_t *
rangemap_create(void)
{
    rangemap_t *rmap = (rangemap_t*)malloc(sizeof(rangemap_t));
    if (rmap == NULL) return NULL;
    rmap->cur_elt = NULL;

    /* have to hand-initialize this rather than use LIST_HEAD_INITIALIZER() */
    rmap->list.lh_first = NULL;

    return rmap;
}

void
rangemap_destroy(rangemap_t *rmap)
{
    while (! LIST_EMPTY(&rmap->list)) {
        struct rangemap_elt *elt = LIST_FIRST(&rmap->list);
        LIST_REMOVE(elt, next);
        free(elt);
    }
    free(rmap);
}

uint32_t
rangemap_get_elt_length(const rangemap_t *rmap)
{
    return rmap->cur_elt->length;
}

uint32_t
rangemap_get_elt_start(const rangemap_t *rmap)
{
    return rmap->cur_elt->start;
}

int
rangemap_is_empty(const rangemap_t *rmap)
{
    return LIST_EMPTY(&rmap->list);
}

int
rangemap_next_elt(rangemap_t *rmap)
{
    if (LIST_NEXT(rmap->cur_elt, next) == NULL) {
        errno = ESPIPE;
        return -1;
    }

    rmap->cur_elt = LIST_NEXT(rmap->cur_elt, next);
    return 0;
}

int
rangemap_put(rangemap_t *rmap, uint32_t start, uint32_t length)
{
    struct rangemap_elt *elt, *last = NULL;

    LIST_FOREACH(elt, &rmap->list, next) {
        int result = compare_elts(elt, start, length);
        switch (result) {
        case 0:   /* elts are mergeable */
            merge_elts(elt, start, length);  /* merge new elt into elt */
            compact_list(rmap);
            return 0;
        case -1:  /* new elt needs to go after this elt (just keep looping) */
            break;
        case 1: { /* new elt needs to go before this elt */
            struct rangemap_elt *e = (struct rangemap_elt*)
                malloc(sizeof(struct rangemap_elt));
            if (e == NULL) return -1;
            e->start = start;
            e->length = length;
            LIST_INSERT_BEFORE(elt, e, next);
            /* no need to call compact_list() */
            return 0;
        }
        default:
            assert(0  /* invalid return value from compare_elts */);
        }

        last = elt;
    }

    /* no more elements; insert at the end */
    struct rangemap_elt *e = (struct rangemap_elt*)
        malloc(sizeof(struct rangemap_elt));
    if (e == NULL) return -1;
    e->start = start;
    e->length = length;

    if (LIST_EMPTY(&rmap->list)) {
        LIST_INSERT_HEAD(&rmap->list, e, next);
    } else {
        assert(last != NULL);
        LIST_INSERT_AFTER(last, e, next);
    }
    return 0;
}

void
rangemap_reset_elt(rangemap_t *rmap)
{
    rmap->cur_elt = LIST_FIRST(&rmap->list);
}


/********************/
/*  STATIC METHODS  */
/********************/

static void
compact_list(rangemap_t *rmap)
{
    struct rangemap_elt *elt;
    LIST_FOREACH(elt, &rmap->list, next) {
        struct rangemap_elt *next_elt = LIST_NEXT(elt, next);
        if (next_elt == NULL) break;
        int result = compare_elts(elt, next_elt->start, next_elt->length);
        assert(result != 1);  /* result == 1 means the ordering was wrong */

        if (result == 0) {
            /* mergeable */
            merge_elts(elt, next_elt->start, next_elt->length);
            LIST_REMOVE(next_elt, next);
            free(next_elt);
        }
    }
}

/*
 * returns 0 if mergeable, -1 if elt must go before eltB (defined by the start
 * and length parameters), and 1 if eltB must go before eltA.
*/
static int
compare_elts(const struct rangemap_elt *elt, uint32_t start, uint32_t length)
{
    uint32_t eltA_tail = elt->start + elt->length;
    uint32_t eltB_tail = start + length;

    if (elt->start <= start) {
        if (eltA_tail >= start) {
            return 0;  /* mergeable */
        } else {  /* eltA_tail < start */
            /* eltA must go before eltB */
            return -1;
        }
    } else {  /* eltA->start > start */
        if (eltB_tail >= elt->start) {
            return 0;  /* mergeable */
        } else {  /* eltB_tail < eltA->start */
            /* eltB must go before eltA */
            return 1;
        }
    }
}

/*
 * returns whether 'elt' was actually changed at all (if the range
 * [start:(start+length)] is wholely contained within elt, then elt will not be
 * changed at all).
 */
static void
merge_elts(struct rangemap_elt *elt, uint32_t start, uint32_t length)
{
#define max(a,b) (a > b ? a : b)
#define min(a,b) (a < b ? a : b)

    uint32_t newend = max(elt->start + elt->length, start + length);
    elt->start = min(elt->start, start);
    elt->length = newend - elt->start;

#undef max
#undef min
}
