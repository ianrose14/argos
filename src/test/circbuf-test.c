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

/* local includes */
#include "circbuf.h"

#define VERBOSE 0

static void
check_value(const char *func, int line, int val, int expected)
{
    if (val != expected) {
        fprintf(stderr, "FAILURE at line %d: \"%s\" returned %d, expected %d\n",
            line, func, val, expected);
        abort();
    }
}

#define TESTFUNC(func, rv, buf, expected)                               \
    test_func_helper(func, __LINE__, rv, buf, expected);
    
static void
test_func_helper(const char *func, int line, int rv, struct circbuf *buf,
    int expected[])
{
    printf("%s\n", func);
    check_value(func, line, rv, expected[0]);

    if (rv == -1) {
        printf("    fail! (%s)\n", strerror(errno));
    } else {
        printf("    success! (rv=%d)\n", rv);

        int val = circbuf_len(buf);
        if (VERBOSE) printf("    length    = %u\n", val);
        check_value("circbuf_len()", line, val, expected[1]);
        
        val = circbuf_remaining(buf);
        if (VERBOSE) printf("    remaining = %u\n", val);
        check_value("circbuf_remaining()", line, val, expected[2]);
        
        val = circbuf_readable(buf);
        if (VERBOSE) printf("    readable  = %u\n", val);
        check_value("circbuf_readable()", line, val, expected[3]);
        
        val = circbuf_writable(buf);
        if (VERBOSE) printf("    writable  = %u\n", val);
        check_value("circbuf_writable()", line, val, expected[4]);

        val = circbuf_head(buf) - buf->arr;
        if (VERBOSE) printf("    headptr   = %u\n", val);
        check_value("circbuf-headptr-position", line, val, expected[5]);
        
        val = circbuf_tail(buf) - buf->arr;
        if (VERBOSE) printf("    tailptr   = %u\n", val);
        check_value("circbuf-tailptr-position", line, val, expected[6]);
    }
}

static void
unpack_tests(struct circbuf *buf)
{
    char data[2048];
    memset(data, 'x', sizeof(data));

    uint8_t c = 64;
    uint16_t s = 512;
    uint32_t i = 1024;
    uint64_t l = 2048;

    char desc[1024];
    snprintf(desc, sizeof(desc), "circbuf_pack(bsil) of (%hhu, %hu, %u, %llu)",
        c, s, i, l);

    int start = circbuf_head(buf) - buf->arr;
    assert((start == 0) || (start == 1019));

    /*
     * 0 - return value
     * 1 - length
     * 2 - remaining
     * 3 - readable
     * 4 - writable
     * 5 - headptr
     * 6 - tailptr
     */
    int expected_vals[7];

    expected_vals[0] = 15;
    expected_vals[1] = 15;
    expected_vals[2] = 1024 - 15;
    expected_vals[3] = (start == 0) ? 15 : 5;
    expected_vals[4] = 1024 - 15;
    expected_vals[5] = start;
    expected_vals[6] = (start == 0) ? 15 : 10;
    TESTFUNC(desc, circbuf_pack(buf, "bsil", c, s, i, l), buf, expected_vals);

    expected_vals[0] = 15;
    expected_vals[1] = 0;
    expected_vals[2] = 1024;
    expected_vals[3] = 0;
    expected_vals[4] = 1024 - ((start == 0) ? 15 : 10);
    expected_vals[5] = expected_vals[6];
    c = s = i = l = 0;
    TESTFUNC("circbuf_unpack(bsil)",
        circbuf_unpack(buf, "bsil", &c, &s, &i, &l), buf, expected_vals);
    printf("    -->  %hhu, %hu, %u, %llu\n", c, s, i, l);

    expected_vals[0] = 15;
    expected_vals[1] += 15;
    expected_vals[2] -= 15;
    expected_vals[3] = 15;
    expected_vals[4] = 1024 - expected_vals[6] - 15;
    expected_vals[6] += 15;
    TESTFUNC("circbuf_write(15)", circbuf_write(buf, data, 15), buf, expected_vals);

    expected_vals[0] = 15;
    expected_vals[1] = 0;
    expected_vals[2] = 1024;
    expected_vals[3] = 0;
    expected_vals[5] = expected_vals[6];
    TESTFUNC("circbuf_read(15)", circbuf_read(buf, data, 15), buf, expected_vals);

    expected_vals[0] = 0;
    expected_vals[1] = 30;
    expected_vals[2] = 1024-30;
    expected_vals[3] = (start == 0) ? 30 : 5;
    expected_vals[4] = 1024 - 30;
    expected_vals[5] = (start == 0) ? 0 : (1024-5);
    c = s = i = l = 0;
    TESTFUNC("circbuf_unread(30)", circbuf_unread(buf, 30), buf, expected_vals);

    expected_vals[0] = 15;
    expected_vals[1] = 15;
    expected_vals[2] = 1024-15;
    expected_vals[3] = 15;
    expected_vals[4] += (start == 0) ? 0 : 5;
    expected_vals[5] = (start == 0) ? 15 : 10;
    TESTFUNC("circbuf_unpack(bsil)", circbuf_unpack(buf, "bsil", &c, &s, &i, &l), buf, expected_vals);
    printf("    -->  %hhu, %hu, %u, %llu\n", c, s, i, l);

    expected_vals[0] = 0;
    expected_vals[1] = 30;
    expected_vals[2] = 1024-30;
    expected_vals[3] = (start == 0) ? 30 : 5;
    expected_vals[4] = 1024 - 30;
    expected_vals[5] = (start == 0) ? 0 : (1024-5);
    TESTFUNC("circbuf_unread(15)", circbuf_unread(buf, 15), buf, expected_vals);

    expected_vals[0] = 0;
    expected_vals[1] = 31;
    expected_vals[2] -= 1;
    expected_vals[3] = (start == 0) ? 1 : 6;
    expected_vals[4] = 1024 - 31;
    expected_vals[5] = 1024 - ((start == 0) ? 1 : 6);
    TESTFUNC("circbuf_unread(1)", circbuf_unread(buf, 1), buf, expected_vals);
    c = 'q';

    expected_vals[0] = 1;
    expected_vals[1] = 30;
    expected_vals[2] += 1;
    expected_vals[3] = (start == 0) ? 30 : 5;
    expected_vals[4] = 1024 - 30;
    expected_vals[5] = (start == 0) ? 0 : (1024-5);
    TESTFUNC("circbuf_read(1)", circbuf_read(buf, &c, 1), buf, expected_vals);
    check_value("character check", __LINE__, c, 'x');

    expected_vals[0] = 0;
    expected_vals[1] += 993;
    expected_vals[2] -= 993;
    expected_vals[3] = (start == 0) ? 993 : 998;
    expected_vals[4] = 1;
    expected_vals[5] = 1 + ((start == 0) ? 30 : 25);
    TESTFUNC("circbuf_unread(993)", circbuf_unread(buf, 993), buf, expected_vals);

    expected_vals[0] = 0;
    expected_vals[1] = 1024;
    expected_vals[2] = 0;
    expected_vals[3] = (start == 0) ? 994 : 999;
    expected_vals[4] = 0;
    expected_vals[5] = ((start == 0) ? 30 : 25);
    TESTFUNC("circbuf_unread(1)", circbuf_unread(buf, 1), buf, expected_vals);

    expected_vals[0] = -1;
    TESTFUNC("circbuf_unread(1)", circbuf_unread(buf, 1), buf, expected_vals);
}

int main(int argc, char **argv)
{
    struct circbuf *buf = circbuf_create(1024);
    if (buf == NULL) err(1, "circbuf_create");

    char data[2048];
    memset(data, 'x', sizeof(data));

    int expected_vals[7];
    /*
     * 0 - return value
     * 1 - buffer total length
     * 2 - buffer remaining capacity
     * 3 - buffer readable length
     * 4 - buffer writable length
     * 5 - buffer headptr position
     * 6 - buffer tailptr position
     */
    
#define INIT(len)                               \
    do {                                        \
        expected_vals[0] = len;                 \
        expected_vals[1] = len;                 \
        expected_vals[2] = 1024 - len;          \
        expected_vals[3] = len;                 \
        expected_vals[4] = 1024 - len;          \
        expected_vals[5] = 0;                   \
        expected_vals[6] = len;                 \
    } while (0);                                \

    INIT(512);
    TESTFUNC("circbuf_write(512)", circbuf_write(buf, data, 512), buf, expected_vals);

    INIT(1024);
    expected_vals[0] = 512;
    expected_vals[6] = 0;
    TESTFUNC("circbuf_write(512)", circbuf_write(buf, data, 512), buf, expected_vals);

    expected_vals[0] = -1;
    TESTFUNC("circbuf_write(512)", circbuf_write(buf, data, 512), buf, expected_vals);

    printf("-------------------------------------------------------\n");
    printf("circbuf_empty\n");
    circbuf_empty(buf);

    INIT(512);
    TESTFUNC("circbuf_write(512)", circbuf_write(buf, data, 512), buf, expected_vals);

    expected_vals[0] = 256;
    expected_vals[1] -= 256;
    expected_vals[2] += 256;
    expected_vals[3] -= 256;
    expected_vals[5] += 256;
    TESTFUNC("circbuf_headup(256)", circbuf_headup(buf, 256), buf, expected_vals);

    expected_vals[0] = 256;
    expected_vals[1] += 256;
    expected_vals[2] -= 256;
    expected_vals[3] += 256;
    expected_vals[4] -= 256;
    expected_vals[6] += 256;
    TESTFUNC("circbuf_tailup(256)", circbuf_tailup(buf, 256), buf, expected_vals);

    expected_vals[0] = 512;
    expected_vals[1] += 512;
    expected_vals[2] -= 512;
    expected_vals[3] = 512 + 256;
    expected_vals[4] = 0;
    expected_vals[6] = 256;
    TESTFUNC("circbuf_write(512)", circbuf_write(buf, data, 512), buf, expected_vals);

    printf("-------------------------------------------------------\n");
    printf("circbuf_empty\n");
    circbuf_empty(buf);

    expected_vals[0] = 768;
    expected_vals[1] = 768;
    expected_vals[2] = 1024 - 768;
    expected_vals[3] = 768;
    expected_vals[4] = 1024 - 768;
    expected_vals[5] = 0;
    expected_vals[6] = 768;
    TESTFUNC("circbuf_tailup(768)", circbuf_tailup(buf, 768), buf, expected_vals);
        
    expected_vals[0] = 256;
    expected_vals[1] -= 256;
    expected_vals[2] += 256;
    expected_vals[3] -= 256;
    expected_vals[5] += 256;
    TESTFUNC("circbuf_headup(256)", circbuf_headup(buf, 256), buf, expected_vals);

    expected_vals[0] = 255;
    expected_vals[1] += 255;
    expected_vals[2] -= 255;
    expected_vals[3] += 255;
    expected_vals[4] -= 255;
    expected_vals[6] += 255;
    TESTFUNC("circbuf_write(255)", circbuf_write(buf, data, 255), buf, expected_vals);

    expected_vals[0] = 8;
    expected_vals[1] += 8;
    expected_vals[2] -= 8;
    expected_vals[3] += 1;
    expected_vals[4] = (256-7);
    expected_vals[6] = 7;
    TESTFUNC("circbuf_pack(ii)", circbuf_pack(buf, "ii", 3, 4), buf, expected_vals);

    expected_vals[0] = 1;
    expected_vals[1] += 1;
    expected_vals[2] -= 1;
    expected_vals[4] = (256-8);
    expected_vals[6] = 8;
    TESTFUNC("circbuf_write(1)", circbuf_write(buf, data, 1), buf, expected_vals);

    expected_vals[0] = 8;
    expected_vals[1] += 8;
    expected_vals[2] -= 8;
    expected_vals[4] = (256-16);
    expected_vals[6] = 16;
    TESTFUNC("circbuf_pack(ii)", circbuf_pack(buf, "ii", 3, 4), buf, expected_vals);

    printf("-------------------------------------------------------\n");
    printf("circbuf_empty\n");
    circbuf_empty(buf);

    INIT(1020);
    TESTFUNC("circbuf_write(1020)", circbuf_write(buf, data, 1020), buf, expected_vals);

    expected_vals[0] = 1020;
    expected_vals[1] = 0;
    expected_vals[2] = 1024;
    expected_vals[3] = 0;
    expected_vals[4] = 1024;
    expected_vals[5] = 0;
    expected_vals[6] = 0;
    TESTFUNC("circbuf_headup(1020)", circbuf_headup(buf, 1020), buf, expected_vals);

    expected_vals[0] = 100;
    expected_vals[1] = 100;
    expected_vals[2] = 1024 - 100;
    expected_vals[3] = 4;
    expected_vals[4] = 1024-100;
    expected_vals[5] = 1020;
    expected_vals[6] = 96;
    TESTFUNC("circbuf_write(100)", circbuf_write(buf, data, 100), buf, expected_vals);

    expected_vals[0] = 3;
    expected_vals[1] -= 3;
    expected_vals[2] += 3;
    expected_vals[3] = 1;
    expected_vals[4] += 3;
    expected_vals[5] = 1023;
    TESTFUNC("circbuf_headup(3)", circbuf_headup(buf, 3), buf, expected_vals);

    expected_vals[1] -= 1;
    expected_vals[2] += 1;
    expected_vals[3] = expected_vals[1];
    expected_vals[4] += 1;
    expected_vals[5] = 0;
    TESTFUNC("circbuf_headup(1)", circbuf_headup(buf, 1), buf, expected_vals);

    expected_vals[1] -= 1;
    expected_vals[2] += 1;
    expected_vals[3] = expected_vals[1];
    expected_vals[5] = 1;
    TESTFUNC("circbuf_headup(1)", circbuf_headup(buf, 1), buf, expected_vals);

    printf("-------------------------------------------------------\n");
    printf("circbuf_empty\n");
    circbuf_empty(buf);

    unpack_tests(buf);

    printf("-------------------------------------------------------\n");
    printf("circbuf_empty\n");
    circbuf_empty(buf);

    INIT(1019);
    TESTFUNC("circbuf_write(1019)", circbuf_write(buf, data, 1019), buf, expected_vals);

    expected_vals[1] = 1019;
    expected_vals[2] = 1024;
    expected_vals[3] = 0;
    expected_vals[4] = 5;
    expected_vals[5] = 1019;
    expected_vals[6] = 1019;
    TESTFUNC("circbuf_read(1019)", circbuf_read(buf, data, 1019), buf, expected_vals);

    unpack_tests(buf);

    circbuf_destroy(buf);

    printf("\n"
        "*******************\n"
        "All tests complete!\n"
        "*******************\n"
        "\n");

    return 0;
}
