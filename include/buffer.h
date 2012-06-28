/*
 * Author: Ian Rose
 * Date Created: Aug 28, 2009
 *
 * Basic buffer implementation.
 */

#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif 


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct buffer {
    u_char *arr;
    size_t arrlen;
    size_t head;
    size_t datalen;
};


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

void buffer_compact(struct buffer *buf);

struct buffer *buffer_create(size_t size);

void buffer_destroy(struct buffer *buf);

int buffer_discard(struct buffer *buf, size_t len);

#ifndef __cplusplus
inline
#endif
void buffer_empty(struct buffer *buf);

int buffer_ensure_space(struct buffer *buf, size_t len);

int buffer_expand(struct buffer *buf, size_t len);

#ifndef __cplusplus
inline
#endif
u_char *buffer_head(struct buffer *buf);

#ifndef __cplusplus
inline
#endif
size_t buffer_len(const struct buffer *buf);

ssize_t buffer_pack(struct buffer *buf, const char *fmt, ...);

ssize_t buffer_read(struct buffer *buf, void *data, size_t len);

ssize_t buffer_read_all(struct buffer *buf, void *data, size_t len);

#ifndef __cplusplus
inline
#endif
size_t buffer_remaining(const struct buffer *buf);

#ifndef __cplusplus
inline
#endif
size_t buffer_size(const struct buffer *buf);

#ifndef __cplusplus
inline
#endif
u_char *buffer_tail(struct buffer *buf);

int buffer_truncate(struct buffer *buf, size_t len);

ssize_t buffer_write(struct buffer *buf, const void *data, size_t len);

ssize_t buffer_write_all(struct buffer *buf, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _BUFFER_H_ */
