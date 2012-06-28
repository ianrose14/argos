/*
 * Author: Ian Rose
 * Date Created: Apr 3, 2009
 *
 * A data structure for keeping track of ranges of numbers.  For example, you
 * can store "1-10, 10-15, 18-20, and 100-150" and then later you can walk
 * through the net results (which are "1-15, 18-20 and 100-150").
 */

#ifndef _RANGEMAP_H_
#define _RANGEMAP_H_

#include <unistd.h>
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif 


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct rangemap_elt {
    uint32_t start, length;
    LIST_ENTRY(rangemap_elt) next;
};

LIST_HEAD(rangemap_elt_list, rangemap_elt);

struct rangemap {
    struct rangemap_elt *cur_elt;
    struct rangemap_elt_list list;
};

typedef struct rangemap rangemap_t;


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

/*
 * returns whether the entire range specified (from start to start+len) is
 * contained in the rangemap.
 */
int rangemap_contains(const rangemap_t *rmap, uint32_t start, uint32_t len);

rangemap_t *rangemap_create(void);

void rangemap_destroy(rangemap_t *rmap);

/* returns the length (or start) of the *current* element of the rangemap */
uint32_t rangemap_get_elt_length(const rangemap_t *rmap);
uint32_t rangemap_get_elt_start(const rangemap_t *rmap);

int rangemap_is_empty(const rangemap_t *rmap);

/*
 * advances the internal pointer to the next element, or returns -1 if there are
 * no more (the current element is the last one).
 */
int rangemap_next_elt(rangemap_t *rmap);

int rangemap_put(rangemap_t *rmap, uint32_t start, uint32_t len);

/* resets the internal pointer to the first element */
void rangemap_reset_elt(rangemap_t *rmap);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _RANGEMAP_H_ */
