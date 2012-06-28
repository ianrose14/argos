/*
 * Author: Ian Rose
 * Date Created: Apr 3, 2009
 *
 * Growable array.
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* local includes */
#include "vector.h"


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

vector_t *
vector_create(size_t element_size, int init_capacity, enum vector_growth growth,
    int growth_elts)
{
    vector_t *vec = (vector_t*)malloc(sizeof(vector_t));
    if (vec == NULL) return NULL;

    size_t alloc_size = init_capacity*element_size;

    vec->size = alloc_size;
    vec->elt_size = element_size;
    vec->valid_len = 0;
    vec->data = malloc(alloc_size);
    vec->growth = growth;
    vec->growth_size = growth_elts*element_size;

    if (vec->data == NULL) {  /* malloc() fail */
        free(vec);
        return NULL;
    }

    return vec;
}

void
vector_destroy(vector_t *vec)
{
    free(vec->data);
    free(vec);
}

void
vector_get(vector_t *vec, int index, void *data)
{
    assert(index < vec->valid_len);

    size_t memindex = index*vec->elt_size;
    memcpy(data, vec->data + memindex, vec->elt_size);
}

int
vector_set(vector_t *vec, int index, void *data)
{
    size_t memindex = index*vec->elt_size;
    size_t reclen = memindex + vec->elt_size;
    if (reclen > vec->size) {
        size_t newsize;
        if (reclen > (vec->size + vec->growth_size))
            newsize = reclen;
        else
            newsize = vec->size + vec->growth_size;

        void *newptr = realloc(vec->data, newsize);
        if (newptr == NULL) return -1;
        vec->data = newptr;
        if (vec->growth == VECTOR_GROWTH_DBL)
            vec->growth_size *= 2;
    }

    memcpy(vec->data + memindex, data, vec->elt_size);
    vec->valid_len = index + 1;
    return 0;
}
