/*
 * Author: Ian Rose
 * Date Created: Apr 3, 2009
 *
 * Growable array.
 */

#ifndef _VECTOR_H_
#define _VECTOR_H_

#ifdef __cplusplus
extern "C" {
#endif 

/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

enum vector_growth { VECTOR_GROWTH_ADD=0, VECTOR_GROWTH_DBL };

struct vector {
    size_t size;                /* total amount of allocated memory */
    size_t elt_size;            /* size of each element */
    int valid_len;              /* index range of inserted elements */
    /* valid_len is not necessary, but provides (weak) bounds checking */
    char *data;                 /* pointer to allocated memory */
    enum vector_growth growth;  /* type of growth */
    size_t growth_size;         /* how much to grow by */
};

typedef struct vector vector_t;


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

vector_t *vector_create(size_t element_size, int init_capacity,
    enum vector_growth growth, int growth_elts);

void vector_destroy(vector_t *vec);

void vector_get(vector_t *vec, int index, void *value);

int vector_set(vector_t *vec, int index, void *value);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _VECTOR_H_ */
