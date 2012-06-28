/*
 * Author: Ian Rose
 * Date Created: Jun 7, 2009
 *
 * Binary-heap implementation (header file only - implementation is all macros).
 */

#ifndef _BINHEAP_H_
#define _BINHEAP_H_

#include <stdlib.h>

typedef struct binheap {
    void *arr;
    int capacity;
    int len;
    size_t elt_size;
} binheap_t;

#define HEAP_NOMEM() do { errno = ENOMEM; } while (0)

#define HEAP_DEFAULT_COMPARE(a, b) (a - b)
#define HEAP_COMPARE(a, b) HEAP_DEFAULT_COMPARE(a, b)

#define HEAP_COUNT(heap) ((heap)->len)

#define HEAP_CAPACITY(heap) ((heap)->capacity)

#define HEAP_CREATE(nelts, eltsize, out)                                \
    do {                                                                \
        (out) = (struct binheap*)malloc(sizeof(struct binheap));        \
        if ((out) == NULL)                                              \
            break;                                                      \
        (out)->arr = malloc((nelts)*(eltsize));                         \
        if ((out)->arr == NULL) {                                       \
            free(out);                                                  \
            (out) = NULL;                                               \
            break;                                                      \
        }                                                               \
        (out)->capacity = nelts;                                        \
        (out)->len = 0;                                                 \
        (out)->elt_size = eltsize;                                      \
    } while (0)

#define HEAP_DESTROY(heap)                      \
    do {                                        \
        free((heap)->arr);                      \
        free(heap);                             \
    } while (0)

#define HEAP_ADD(heap, type, key)                              \
    do {                                                       \
        assert(sizeof(type) == (heap)->elt_size);              \
        if ((heap)->len == (heap)->capacity) {                 \
            /* full - need to grow */                          \
            size_t new_elts = ((heap)->capacity)*2;            \
            void *newptr = realloc((heap)->arr,                \
                new_elts*((heap)->elt_size));                  \
            if (newptr == NULL) {                              \
                HEAP_NOMEM();                                  \
                break;                                         \
            }                                                  \
            (heap)->arr = newptr;                              \
            (heap)->capacity = new_elts;                       \
        }                                                      \
        type *a = (type*)((heap)->arr);                        \
        a[(heap)->len] = key;                                  \
        (heap)->len++;                                         \
        HEAP_SIFTUP(heap, type);                               \
    } while (0)

#define HEAP_EXTRACT_ROOT(heap, type, out)                      \
    do {                                                        \
        assert(sizeof(type) == (heap)->elt_size);               \
        if ((heap)->len > 0) {                                  \
            type *a = (type*)((heap)->arr);                     \
            (out) = a[0];                                       \
            a[0] = a[(heap)->len - 1];                          \
            (heap)->len--;                                      \
            HEAP_SIFTDOWN(heap, type);                          \
        }                                                       \
    } while (0);

#define HEAP_ROOT(heap, type, out)                              \
    do {                                                        \
        assert(sizeof(type) == (heap)->elt_size);               \
        if ((heap)->len > 0)                                    \
            (out) = ((type*)((heap)->arr))[0];                  \
    } while (0);                                                \

/*** Macros internal to the implementation. ***/

#define HEAP_SIFTDOWN(heap, type)                              \
    do {                                                       \
        int i = 0;                                             \
        type *a = (type*)((heap)->arr);                        \
        while (1) {                                            \
            int c1 = 2*i + 1;                                  \
            int c2 = 2*i + 2;                                  \
            if (c1 >= (heap)->len)                             \
                break; /* no children */                       \
            if (c2 >= (heap)->len) {                           \
                if (HEAP_COMPARE(a[i], a[c1]) <= 0)            \
                    break;                                     \
                else {                                         \
                    HEAP_SWAP(a[i], a[c1], type);              \
                    i = c1;                                    \
                }                                              \
            }                                                  \
            else if (HEAP_COMPARE(a[c1], a[c2]) <= 0) {        \
                if (HEAP_COMPARE(a[i], a[c1]) <= 0)            \
                    break;                                     \
                else {                                         \
                    HEAP_SWAP(a[i], a[c1], type);              \
                    i = c1;                                    \
                }                                              \
            } else {                                           \
                if (HEAP_COMPARE(a[i], a[c2]) <= 0)            \
                    break;                                     \
                else {                                         \
                    HEAP_SWAP(a[i], a[c2], type);              \
                    i = c2;                                    \
                }                                              \
            }                                                  \
        }                                                      \
    } while (0)

#define HEAP_SIFTUP(heap, type)                         \
    do {                                                \
        int i = (heap)->len - 1;                        \
        type *a = (type*)((heap)->arr);                 \
        while (i > 0) {                                 \
            int parent = (i-1)/2;                       \
            if (HEAP_COMPARE(a[parent], a[i]) <= 0)     \
                break;                                  \
            HEAP_SWAP(a[i], a[parent], type);           \
            i = parent;                                 \
        }                                               \
    } while (0)
    
#define HEAP_SWAP(a, b, type)                        \
      do {                                           \
          type temp = a;                             \
          a = b;                                     \
          b = temp;                                  \
      } while(0)

#endif /* #ifndef _BINHEAP_H_ */
