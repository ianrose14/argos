/*
 * Author: Ian Rose
 * Date Created: Mar 29, 2009
 *
 * Circular buffer implementation.
 */

#ifndef _CIRCBUF_H_
#define _CIRCBUF_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif 


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct circbuf {
    u_char *arr;
    size_t arrlen;
    size_t datalen;
    size_t head_offset;
};


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

struct circbuf *circbuf_create(size_t size);

void circbuf_destroy(struct circbuf *buf);

int circbuf_discard(struct circbuf *buf, size_t len);

inline void circbuf_empty(struct circbuf *buf);

inline u_char *circbuf_head(struct circbuf *buf);

int circbuf_headup(struct circbuf *buf, size_t len);

inline size_t circbuf_len(const struct circbuf *buf);

ssize_t circbuf_pack(struct circbuf *buf, const char * restrict fmt, ...);

int circbuf_read(struct circbuf *buf, void *data, size_t len);

inline size_t circbuf_readable(const struct circbuf *buf);

inline size_t circbuf_remaining(const struct circbuf *buf);

inline size_t circbuf_size(const struct circbuf *buf);

inline size_t circbuf_stored(const struct circbuf *buf);

inline u_char *circbuf_tail(struct circbuf *buf);

int circbuf_tailup(struct circbuf *buf, size_t len);

int circbuf_unread(struct circbuf *buf, ssize_t len);

ssize_t circbuf_unpack(struct circbuf *buf, const char * restrict fmt, ...);

inline size_t circbuf_writable(struct circbuf *buf);

int circbuf_write(struct circbuf *buf, const void *data, size_t len);

int circbuf_unwrite(struct circbuf *buf, ssize_t len);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _CIRCBUF_H_ */
