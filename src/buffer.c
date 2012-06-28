/*
 * Author: Ian Rose
 * Date Created: Aug 28, 2009
 *
 * Basic buffer implementation.
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* local includes */
#include "buffer.h"

#ifdef CLICK_VERSION
CLICK_DECLS
#endif


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

void
buffer_compact(struct buffer *buf)
{
    if (buf->head > 0) {
        memmove(buf->arr, buffer_head(buf), buf->datalen);
        buf->head = 0;
    }
}

struct buffer *
buffer_create(size_t size)
{
    struct buffer *buf = malloc(sizeof(struct buffer));
    if (buf == NULL) return NULL;

    buf->arr = malloc(size);
    if (buf->arr == NULL) {
        free(buf);
        return NULL;
    }

    buf->arrlen = size;
    buf->head = 0;
    buf->datalen = 0;

    return buf;
}

void
buffer_destroy(struct buffer *buf)
{
    free(buf->arr);
    free(buf);
}

int
buffer_discard(struct buffer *buf, size_t len)
{
    if (len > buf->datalen) {
        errno = EINVAL;
        return -1;
    }

    buf->datalen -= len;
    if (buf->datalen == 0)
        buf->head = 0;  /* for efficiency, might as well compact */
    else
        buf->head += len;

    return len;
}

inline void
buffer_empty(struct buffer *buf)
{
    buf->head = 0;
    buf->datalen = 0;
}

int
buffer_ensure_space(struct buffer *buf, size_t len)
{
    if (buffer_remaining(buf) >= len)
        return 1;  /* no need to compact */

    if ((buf->arrlen - buffer_len(buf)) >= len) {
        /* we have the space, but only if we compact */
        buffer_compact(buf);
        assert(buffer_remaining(buf) >= len);
        return 1;
    } else {
        return 0;  /* not enough space, even if we compact */
    }
}

int
buffer_expand(struct buffer *buf, size_t len)
{
    if (len > buffer_remaining(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    buf->datalen += len;
    return len;
}

inline u_char *
buffer_head(struct buffer *buf)
{
    return buf->arr + buf->head;
}

inline size_t
buffer_len(const struct buffer *buf)
{
    return buf->datalen;
}

ssize_t
buffer_pack(struct buffer *buf, const char *fmt, ...)
{
    size_t space = buffer_remaining(buf);

    va_list ap;
    va_start(ap, fmt);
    int rv = vsnprintf((char*)buffer_tail(buf), space, fmt, ap);
    int e = errno;
    va_end(ap);

    if ((rv == -1) || ((size_t)rv >= space)) {
        errno = e;
        return -1;
    }

    return rv;
}

ssize_t
buffer_read(struct buffer *buf, void *data, size_t len)
{
    size_t tocopy = (len > buf->datalen) ? buf->datalen : len;
    memcpy(data, buffer_head(buf), tocopy);
    if (tocopy < buf->datalen) {
        ssize_t rv = buffer_discard(buf, tocopy);
        assert(rv == (ssize_t)tocopy);
    } else {
        assert(tocopy == buf->datalen);
        buf->head = 0;
        buf->datalen = 0;
    }
    return tocopy;
}

ssize_t
buffer_read_all(struct buffer *buf, void *data, size_t len)
{
    if (len > buf->datalen) {
        errno = EINVAL;
        return -1;
    }

    memcpy(data, buffer_head(buf), len);
    ssize_t rv = buffer_discard(buf, len);
    assert(rv == (ssize_t)len);
    return len;
}

inline size_t
buffer_remaining(const struct buffer *buf)
{
    return buf->arrlen - buf->datalen - buf->head;
}

inline size_t
buffer_size(const struct buffer *buf)
{
    return buf->arrlen;
}

inline u_char *
buffer_tail(struct buffer *buf)
{
    return buf->arr + buf->head + buf->datalen;
}

int
buffer_truncate(struct buffer *buf, size_t len)
{
    if (len > buf->datalen) {
        errno = EINVAL;
        return -1;
    }

    buf->datalen -= len;
    if (buf->datalen == 0)
        buf->head = 0;  /* for efficiency, might as well compact */

    return len;
}

ssize_t
buffer_write(struct buffer *buf, const void *data, size_t len)
{
    size_t space = buffer_remaining(buf);
    size_t tocopy = (len > space) ? space : len;
    memcpy(buffer_tail(buf), data, tocopy);
    buf->datalen += tocopy;
    assert(buf->datalen <= buf->arrlen);
    return tocopy;
}

ssize_t
buffer_write_all(struct buffer *buf, const void *data, size_t len)
{
    if (len > buffer_remaining(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memcpy(buffer_tail(buf), data, len);
    buf->datalen += len;
    assert(buf->datalen <= buf->arrlen);
    return len;
}

#ifdef CLICK_VERSION
CLICK_ENDDECLS
ELEMENT_PROVIDES(buffer)
#endif
