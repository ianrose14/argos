/*
 * Author: Ian Rose
 * Date Created: June 1, 2009
 *
 * Tests circbuf-test.c
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* local includes */
#include "binheap.h"
#include "utlist.h"
#include "orion/list.h"

#define VERBOSE 0
#define INIT_CAPACITY 5
#define NUM_RANDOM_ITERS 10000

/* TYPE DECLARATIONS */

struct listentry {
    int val;
    struct listentry *next;
    struct listentry *prev;
};

struct heapentry {
    int somejunk;
    int val;
    char morejunk[13];
    struct timeval *randomptr;
};


/* STATIC VARIABLES */

static binheap_t *heap = NULL;
static struct listentry *listhead = NULL;


/* METHODS */

static void add_int_item(int val)
{
    HEAP_ADD(heap, int, val);

    struct listentry *entry = (struct listentry *)malloc(sizeof(struct listentry));
    assert(entry != NULL);
    entry->val = val;

    if (listhead == NULL) {
        DL_APPEND(listhead, entry);
        return;
    }
    
    struct listentry *elt;
    DL_FOREACH(listhead, elt) {
        if (elt->val >= val) {
            DL_INSERT_BEFORE(listhead, elt, entry);
            return;
        }
    }

    DL_APPEND(listhead, entry);
    return;
}

static int pop_int_item(void)
{
    assert(HEAP_COUNT(heap) > 0);
    assert(listhead != NULL);

    int key = -1;
    HEAP_ROOT(heap, int, key);
    assert(key != -1);

    int key2 = -1;
    HEAP_EXTRACT_ROOT(heap, int, key2);
    assert(key2 == key);

    if (listhead->val != key) {
        fprintf(stderr, "error.  listhead->val=%d, heap-min=%d\n",
            listhead->val, key);
        abort();
    }

    struct listentry *elt = listhead;
    DL_DELETE(listhead, elt);
    free(elt);
    return key;
}

#undef HEAP_COMPARE
#define HEAP_COMPARE(a, b) (a->val - b->val)

static void add_struct_item(int val)
{
    struct heapentry *hentry = (struct heapentry*)malloc(sizeof(struct heapentry));
    hentry->val = val;
    HEAP_ADD(heap, struct heapentry*, hentry);

    struct listentry *entry = (struct listentry *)malloc(sizeof(struct listentry));
    assert(entry != NULL);
    entry->val = val;

    if (listhead == NULL) {
        DL_APPEND(listhead, entry);
        return;
    }
    
    struct listentry *elt;
    DL_FOREACH(listhead, elt) {
        if (elt->val >= val) {
            DL_INSERT_BEFORE(listhead, elt, entry);
            return;
        }
    }

    DL_APPEND(listhead, entry);
    return;
}

static int pop_struct_item(void)
{
    assert(HEAP_COUNT(heap) > 0);
    assert(listhead != NULL);

    struct heapentry *hentry = NULL;
    HEAP_ROOT(heap, struct heapentry*, hentry);
    assert(hentry != NULL);

    struct heapentry *hentry2 = NULL;
    HEAP_EXTRACT_ROOT(heap, struct heapentry*, hentry2);
    assert(hentry == hentry2);

    if (listhead->val != hentry->val) {
        fprintf(stderr, "error.  listhead->val=%d, heap-min=%d\n",
            listhead->val, hentry->val);
        abort();
    }

    int val = hentry->val;
    free(hentry);

    struct listentry *elt = listhead;
    DL_DELETE(listhead, elt);
    free(elt);
    return val;;
}

#undef HEAP_COMPARE
#define HEAP_COMPARE(a, b) HEAP_DEFAULT_COMPARE(a, b)

static const char *list_dump(void)
{
    static char cbuf[1024];
    char tmp[64];
    cbuf[0] = '\0';
    strlcat(cbuf, "[", sizeof(cbuf));

    int first = 1;
    struct listentry *elt;
    DL_FOREACH(listhead, elt) {
        snprintf(tmp, sizeof(tmp), (first ? "%d" : ", %d"), elt->val);
        strlcat(cbuf, tmp, sizeof(cbuf));
        first = 0;
    }

    strlcat(cbuf, "]", sizeof(cbuf));
    return cbuf;
}

int main(int argc, char **argv)
{
    int seed;
    int hiwater = 0;

    if (argc > 1)
        seed = atoi(argv[1]);
    else
        seed = time(NULL);

    printf("random seed = %d\n", seed);
    srandom(seed);

    /*
     * INTEGER TESTS
     */
    printf("---------------------------------------------------------\n");
    printf("  starting integer tests\n");
    printf("---------------------------------------------------------\n");

    HEAP_CREATE(INIT_CAPACITY, sizeof(int), heap);
    if (heap == NULL)
        err(1, "HEAP_CREATE");

    for (int i=0; i < 5; i++) {
        int val = random() & 0xFFFF;
        add_int_item(val);
        if (VERBOSE) printf(" added %4d  -  %s\n", val, list_dump());
    }

    for (int i=0; i < NUM_RANDOM_ITERS; i++) {
        int do_add = random() & 0x3;  /* 3/4 chance of adding */

        if (HEAP_COUNT(heap) == 0) {
            assert(listhead == NULL);
            if (VERBOSE) printf(" (heap empty)\n");
            do_add = 1;
        }

        if (HEAP_COUNT(heap) > hiwater)
            hiwater = HEAP_COUNT(heap);

        if (do_add) {
            int grow = (HEAP_COUNT(heap) == HEAP_CAPACITY(heap));
            if (grow && VERBOSE) printf(" (heap full)\n");

            int val = random() & 0xFFFF;
            add_int_item(val);
            if (VERBOSE) printf("%d: added %4d  -  %s\n", i, val, list_dump());
            if (grow && VERBOSE) printf(" capacity is now %d\n", HEAP_CAPACITY(heap));
        } else {
            int val = pop_int_item();
            if (VERBOSE) printf("%d: popped %4d  -  %s\n", i, val, list_dump());
        }
    }

    while (HEAP_COUNT(heap) > 0) {
        int val = pop_int_item();
        if (VERBOSE) printf("-: popped %4d  -  %s\n", val, list_dump());
    }

    HEAP_DESTROY(heap);

    printf("\n  Integer Tests Complete!  high-water-mark=%d\n\n", hiwater);

    /*
     * STRUCT TESTS
     */
    hiwater = 0;

    printf("---------------------------------------------------------\n");
    printf("  starting struct tests\n");
    printf("---------------------------------------------------------\n");

    HEAP_CREATE(INIT_CAPACITY, sizeof(struct heapentry*), heap);
    if (heap == NULL)
        err(1, "HEAP_CREATE");

    for (int i=0; i < 5; i++) {
        int val = random() & 0xFFFF;
        add_struct_item(val);
        if (VERBOSE) printf(" added %4d  -  %s\n", val, list_dump());
    }

    for (int i=0; i < NUM_RANDOM_ITERS; i++) {
        int do_add = random() & 0x3;  /* 3/4 chance of adding */

        if (HEAP_COUNT(heap) == 0) {
            assert(listhead == NULL);
            if (VERBOSE) printf(" (heap empty)\n");
            do_add = 1;
        }

        if (HEAP_COUNT(heap) > hiwater)
            hiwater = HEAP_COUNT(heap);

        if (do_add) {
            int grow = (HEAP_COUNT(heap) == HEAP_CAPACITY(heap));
            if (grow && VERBOSE) printf(" (heap full)\n");

            int val = random() & 0xFFFF;
            add_struct_item(val);
            if (VERBOSE) printf("%d: added %4d  -  %s\n", i, val, list_dump());
            if (grow && VERBOSE) printf(" capacity is now %d\n", HEAP_CAPACITY(heap));
        } else {
            int val = pop_struct_item();
            if (VERBOSE) printf("%d: popped %4d  -  %s\n", i, val, list_dump());
        }
    }

    while (HEAP_COUNT(heap) > 0) {
        int val = pop_struct_item();
        if (VERBOSE) printf("-: popped %4d  -  %s\n", val, list_dump());
    }

    HEAP_DESTROY(heap);

    printf("\n  Struct Tests Complete!  high-water-mark=%d\n\n", hiwater);

    printf("******************************\n");
    printf("**    All Tests Complete    **\n");
    printf("******************************\n");
    return 0;
}
