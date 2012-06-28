/*
 * Author: Ian Rose
 * Date Created: May 29, 2009
 *
 * Circular buffer implementation.
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* local includes */
#include "circbuf.h"


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static ssize_t parse_format(const char * restrict fmt);



/**********************/
/*  EXTERNAL METHODS  */
/**********************/

struct circbuf *
circbuf_create(size_t size)
{
    struct circbuf *buf = (struct circbuf*)malloc(sizeof(struct circbuf));
    if (buf == NULL) return NULL;

    buf->arr = (u_char*)malloc(size);
    if (buf->arr == NULL) {
        free(buf);
        return NULL;
    }

    buf->arrlen = size;
    buf->datalen = 0;
    buf->head_offset = 0;

    return buf;
}

void
circbuf_destroy(struct circbuf *buf)
{
    free(buf->arr);
    free(buf);
}

int
circbuf_discard(struct circbuf *buf, size_t len)
{
    if (len > buf->datalen) {
        errno = E2BIG;
        return -1;
    }

    size_t readable = circbuf_readable(buf);
    assert(readable <= buf->arrlen);

    buf->datalen -= len;
    if (len > readable) {
        buf->head_offset += (len - buf->arrlen);
    } else {
        buf->head_offset += len;
    }

    if (buf->head_offset == buf->arrlen) buf->head_offset = 0;
    assert(buf->head_offset < buf->arrlen);

    return len;
}

inline void
circbuf_empty(struct circbuf *buf)
{
    buf->head_offset = 0;
    buf->datalen = 0;
}

inline u_char *
circbuf_head(struct circbuf *buf)
{
    return buf->arr + buf->head_offset;
}

int
circbuf_headup(struct circbuf *buf, size_t len)
{
    if (len > buf->datalen) {
        errno = EINVAL;
        return -1;
    }

    /* wrapping is not allowed */
    if ((buf->head_offset + len) > buf->arrlen) {
        errno = EINVAL;
        return -1;
    }

    buf->datalen -= len;
    buf->head_offset += len;

    if (buf->head_offset == buf->arrlen) buf->head_offset = 0;
    assert(buf->head_offset < buf->arrlen);

    return len;
}

inline size_t
circbuf_len(const struct circbuf *buf)
{
    return buf->datalen;
}

ssize_t
circbuf_pack(struct circbuf *buf, const char * restrict fmt, ...)
{
    /* first validate the format argument and calculate required space */
    size_t reqlen = parse_format(fmt);
    if (reqlen == -1) return -1;

    if (reqlen > circbuf_remaining(buf)) {
        errno = ENOSPC;
        return -1;
    }

    va_list args;
    va_start(args, fmt);

    char b;
    uint32_t i;
    uint64_t l;
    uint16_t s;

    int rv;

    for (const char *c = fmt; *c != '\0'; c++) {
        switch (*c) {
        case 'b':  /* byte */
        case 'c':  /* char (synonym for byte) */
            b = (char)va_arg(args, int);  /* char is promoted to int */
            rv = circbuf_write(buf, &b, 1);
            assert(rv != -1);
            break;
        case 'd':  /* integer (4 bytes) */
        case 'i':  /* integer (4 bytes) */
            i = va_arg(args, uint32_t);
            rv = circbuf_write(buf, &i, 4);
            assert(rv != -1);
            break;
        case 'l':  /* long (8 bytes) */
            l = va_arg(args, uint64_t);
            rv = circbuf_write(buf, &l, 8);
            assert(rv != -1);
            break;
        case 's':  /* short (2 bytes) */
            s = (uint16_t)va_arg(args, int);  /* short is promoted to int */
            rv = circbuf_write(buf, &s, 2);
            assert(rv != -1);
            break;
        case 'x':  /* non-capturing byte */
            b = '0';
            rv = circbuf_write(buf, &b, 1);
            assert(rv != -1);
            break;
        default:
            assert(0  /* invalid formatting character */);
        }
    }

    va_end(args);

    return reqlen;
}

int
circbuf_read(struct circbuf *buf, void *data, size_t len)
{
    if (len > buf->datalen) {
        errno = E2BIG;
        return -1;
    }

    size_t readable = circbuf_readable(buf);
    assert(readable <= buf->arrlen);

    if (len > readable) {
        memcpy(data, circbuf_head(buf), readable);

        size_t leftover = len - readable;
        memcpy((char*)data + readable, buf->arr, leftover);

        buf->head_offset += (len - buf->arrlen);
    } else {
        memcpy(data, circbuf_head(buf), len);
        buf->head_offset += len;
    }

    buf->datalen -= len;

    if (buf->head_offset == buf->arrlen) buf->head_offset = 0;
    assert(buf->head_offset < buf->arrlen);
    return len;
}

inline size_t
circbuf_readable(const struct circbuf *buf)
{
    /* note: this is tricky - draw a picture! */
    if ((buf->head_offset + buf->datalen) > buf->arrlen)
        /* data wraps within buffer */
        return (buf->arrlen - buf->head_offset);
    else
        return buf->datalen;
}

inline size_t
circbuf_remaining(const struct circbuf *buf)
{
    return buf->arrlen - buf->datalen;
}

inline size_t
circbuf_size(const struct circbuf *buf)
{
    return buf->arrlen;
}

inline size_t
circbuf_stored(const struct circbuf *buf)
{
    return buf->datalen;
}

inline u_char *
circbuf_tail(struct circbuf *buf)
{
    /* note: this is tricky - draw a picture! */
    if ((buf->head_offset + buf->datalen) >= buf->arrlen)
        /* data wraps within buffer */
        return buf->arr + ((buf->head_offset + buf->datalen) - buf->arrlen);
    else
        return buf->arr + (buf->head_offset + buf->datalen);
}

int
circbuf_tailup(struct circbuf *buf, size_t len)
{
    if (len > circbuf_remaining(buf)) {
        errno = EINVAL;
        return -1;
    }

    buf->datalen += len;
    return len;
}

ssize_t
circbuf_unpack(struct circbuf *buf, const char * restrict fmt, ...)
{
    /* first validate the format argument and calculate required space */
    size_t reqlen = parse_format(fmt);
    if (reqlen == -1) return -1;

    if (reqlen > buf->datalen) {
        errno = E2BIG;
        return -1;
    }

    va_list args;
    va_start(args, fmt);

    char *b;
    uint32_t *i;
    uint64_t *l;
    uint16_t *s;

    char nullbyte;

    int rv;
    size_t start_len = buf->datalen;

    for (const char *c = fmt; *c != '\0'; c++) {
        switch (*c) {
        case 'b':  /* byte */
        case 'c':  /* char (synonym for byte) */
            b = va_arg(args, char*);
            rv = circbuf_read(buf, b, 1);
            assert(rv != -1);
            break;
        case 'd':  /* integer (4 bytes) */
        case 'i':  /* integer (4 bytes) */
            i = va_arg(args, uint32_t*);
            rv = circbuf_read(buf, i, 4);
            assert(rv != -1);
            break;
        case 'l':  /* long (8 bytes) */
            l = va_arg(args, uint64_t*);
            rv = circbuf_read(buf, l, 8);
            assert(rv != -1);
            break;
        case 's':  /* short (2 bytes) */
            s = va_arg(args, uint16_t*);
            rv = circbuf_read(buf, s, 2);
            assert(rv != -1);
            break;
        case 'x':  /* non-capturing byte */
            rv = circbuf_read(buf, &nullbyte, 1);
            assert(rv != -1);
            break;
        default:
            assert(0  /* invalid formatting character */);
        }
    }

    va_end(args);

    assert(buf->datalen == (start_len - reqlen));

    return reqlen;
}

int
circbuf_unread(struct circbuf *buf, ssize_t len)
{
    if (len > circbuf_remaining(buf)) {
        errno = ENOSPC;
        return -1;
    }

    if (buf->head_offset < len) {
        len -= buf->head_offset;

        buf->datalen += buf->head_offset;
        buf->head_offset = buf->arrlen;
    }

    buf->head_offset -= len;
    buf->datalen += len;

    return len;
}

inline size_t
circbuf_writable(struct circbuf *buf)
{
    if (buf->datalen == buf->arrlen)
        return 0;

    u_char *tailptr = circbuf_tail(buf);
    u_char *headptr = circbuf_head(buf);

    if (headptr > tailptr)
        /* data wraps within buffer */
        return headptr - tailptr;
    else
        return (buf->arr + buf->arrlen) - tailptr;
}

int
circbuf_write(struct circbuf *buf, const void *data, size_t len)
{
    if (len > circbuf_remaining(buf)) {
        errno = ENOSPC;
        return -1;
    }

    size_t writable = circbuf_writable(buf);

    if (len > writable) {
        memcpy(circbuf_tail(buf), data, writable);

        size_t leftover = len - writable;
        memcpy(buf->arr, (char*)data + writable, leftover);
    } else {
        memcpy(circbuf_tail(buf), data, len);
    }

    buf->datalen += len;

    assert(buf->datalen <= buf->arrlen);
    return len;
}

int
circbuf_unwrite(struct circbuf *buf, ssize_t len)
{
    if (len > buf->datalen) {
        errno = E2BIG;
        return -1;
    }

    buf->datalen -= len;
    return len;
}


/********************/
/*  STATIC METHODS  */
/********************/

static ssize_t
parse_format(const char * restrict fmt)
{
    ssize_t reqlen = 0;

    for (const char *c = fmt; *c != '\0'; c++) {
        switch (*c) {
        case 'b':  /* byte */
        case 'c':  /* char (synonym for byte) */
        case 'x':  /* non-capturing byte */
            reqlen++;
            break;
        case 'd':  /* integer (4 bytes) */
        case 'i':  /* integer (synonym) */
            reqlen += 4;
            break;
        case 'l':  /* long (8 bytes) */
            reqlen += 8;
            break;
        case 'h':  /* half-integer (synonym for short) */
        case 's':  /* short (2 bytes) */
            reqlen += 2;
            break;
        default:
            errno = EINVAL;
            return -1;
        }
    }
    return reqlen;
}
