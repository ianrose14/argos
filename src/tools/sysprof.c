/*
 * Author: Ian Rose
 * Date Created: Sep 6, 2009
 *
 * Performs some basic timing tests to measure system performance.
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "quicklz.h"

/*****************/
/*  DEFINITIONS  */
/*****************/

#define MAX_BUF_SIZE (1024*1024*10)

typedef int (*test_func)(size_t);


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static ssize_t time_test(test_func, size_t, struct timeval*);
static ssize_t compress_quicklz(size_t);
static ssize_t getrusage_test(size_t);
static ssize_t gettimeofday_test(size_t);
static ssize_t itimer_test(size_t);
static ssize_t memcpy_test(size_t);
static ssize_t write_dev_null(size_t);
static ssize_t write_tmp(size_t);


/**********************/
/*  STATIC VARIABLES  */
/**********************/

static char src_buf[MAX_BUF_SIZE];
static char dst_buf[MAX_BUF_SIZE];
static char qlz_scratch[QLZ_SCRATCH_COMPRESS];


/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    /* touch memory to make sure compiler doesn't screw us */
    src_buf[0] = '4';
    src_buf[MAX_BUF_SIZE-1] = '5';
    dst_buf[0] = '6';
    dst_buf[MAX_BUF_SIZE-1] = '7';

    /*
     * System Call Measurements
     */
    test_func syscall_tests[] = { getrusage_test, gettimeofday_test, itimer_test };
    char *syscall_test_names[] = { "getrusage", "gettimeofday", "itimer" };

    printf("System Call Measurements\n"
        "-----------------------------------------------------------\n");

    for (int i=0; i < 3; i++) {
        test_func f = syscall_tests[i];

        size_t iters[] = { 1, 10, 100*1000 };
        size_t warmups[] = { 0, 0, 1000 };

        for (int j=0; j < 3; j++) {
            /* warm up! */
            if (warmups[j] > 0)
                f(warmups[j]);

            /* the real deal */
            struct timeval elapsed;
            ssize_t outval = time_test(f, iters[j], &elapsed);

            if (outval < 0)
                errx(1, "%16s test failed: %d", syscall_test_names[i], outval);

            float elapsed_sec = elapsed.tv_sec +
                (float)elapsed.tv_usec/(1000*1000);

            printf("%16s (%d iters) took %5.2f ms (%.2f us/call)\n",
                syscall_test_names[i], iters[j], elapsed_sec*1000,
                (elapsed_sec*1000000)/iters[j]);
        }
    }

    printf("\nBlock-Transfer Measurements\n"
        "-----------------------------------------------------------\n");

    /*
     * Block-Transfer Measurements
     */
    test_func xfer_tests[] = { memcpy_test, write_dev_null, write_tmp };
    char *xfer_test_names[] = { "memcpy", "write-dev-null", "write-tmp" };

    for (int i=0; i < 3; i++) {
        test_func f = xfer_tests[i];
        
        for (size_t buflen=32*1024; buflen <= MAX_BUF_SIZE; buflen *= 2) {
            struct timeval elapsed;
            ssize_t outlen = time_test(f, buflen, &elapsed);

            if (outlen < 0)
                errx(1, "%16s (in: %04d KB) test failed: %d", xfer_test_names[i],
                    buflen/1024, outlen);

            float elapsed_sec = elapsed.tv_sec +
                (float)elapsed.tv_usec/(1000*1000);

            printf("%16s (in: %4dKB, out: %dKB) took %5.2f ms (%.2f MB/s)\n",
                xfer_test_names[i], buflen/1024, outlen/1024, elapsed_sec*1000,
                (buflen/elapsed_sec)/(1024*1024));
        }
    }

    /*
     * Compression Measurements
     */
    test_func compression_tests[] = { compress_quicklz };
    char *compression_test_names[] = { "compress_quicklz" };

    printf("\nCompression Measurements\n"
        "-----------------------------------------------------------\n");

    for (int i=1; i < argc; i++) {
        const char *filename = argv[i];

        size_t total_len = 0;
        int fd = open(filename, O_RDONLY);
        if (fd == -1)
            err(1, "open(%s)", filename);

        filename = basename(filename);

        while (total_len < MAX_BUF_SIZE) {
            ssize_t len = read(fd, src_buf + total_len, MAX_BUF_SIZE - total_len);
            if (len == -1)
                err(1, "read(%s)", filename);
            else if (len == 0)
                break;
            else
                total_len += len;
        }

        printf("%s is %d bytes long\n", filename, total_len);

        for (int j=0; j < 2; j++) {
            test_func f = compression_tests[j];
            struct timeval elapsed;
            ssize_t outlen = time_test(f, total_len, &elapsed);

            if (outlen < 0)
                errx(1, "%16s (%s: %dKB) test failed: %d", compression_test_names[i],
                    filename, total_len/1024, outlen);

            float elapsed_sec = elapsed.tv_sec +
                (float)elapsed.tv_usec/(1000*1000);

            float compression = outlen/(float)total_len;

            printf("%16s(%s): %dKB, out: %dKB (%.1f%%) took %5.2f ms (%.2f MB/s)\n",
                compression_test_names[j], filename, total_len/1024, outlen/1024,
                (1-compression)*100, elapsed_sec*1000, (total_len/elapsed_sec)/(1024*1024));
        }

        close(fd);
    }

    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

static int time_test(test_func f, size_t len, struct timeval *elapsed)
{
    struct timeval start, end;

    if (gettimeofday(&start, NULL) != 0)
        err(1, "gettimeofday");

    ssize_t result = f(len);

    if (gettimeofday(&end, NULL) != 0)
        err(1, "gettimeofday");

    elapsed->tv_sec = end.tv_sec - start.tv_sec;
    if (end.tv_usec >= start.tv_usec)
        elapsed->tv_usec = end.tv_usec - start.tv_usec;
    else {
        elapsed->tv_sec--;
        elapsed->tv_usec = (1000*1000) + end.tv_usec - start.tv_usec;
    }

    return result;
}

static ssize_t
compress_quicklz(size_t len) {
    return qlz_compress(src_buf, dst_buf, len, qlz_scratch);
}

static ssize_t
getrusage_test(size_t iters)
{
    struct rusage rusage;
    for (size_t i=0; i < iters; i++) {
        if (getrusage(RUSAGE_SELF, &rusage) != 0)
            return -1;
    }
    return 0;
}

static ssize_t
gettimeofday_test(size_t iters)
{
    struct timeval now;
    for (size_t i=0; i < iters; i++) {
        if (gettimeofday(&now, NULL) != 0)
            return -1;
    }
    return 0;
}

static ssize_t
itimer_test(size_t iters)
{
    struct itimerval val;
    for (size_t i=0; i < iters; i++) {
        val.it_value.tv_sec = 100;
        val.it_value.tv_usec = 0;
        if (setitimer(ITIMER_VIRTUAL, &val, NULL) != 0)
            return -1;

        if (getitimer(ITIMER_VIRTUAL, &val) != 0)
            return -1;
    }
    return 0;
}

static ssize_t
memcpy_test(size_t len)
{
    memcpy(dst_buf, src_buf, len);
    return len;
}

static ssize_t
write_dev_null(size_t len)
{
    static int fd = -1;

    if (fd == -1) {
        fd = open("/dev/null", O_WRONLY);
        if (fd == -1) err(1, "open(\"/dev/null\")");
    }

    return write(fd, src_buf, len);
}

static ssize_t
write_tmp(size_t len)
{
    static int fd = -1;
    static char tmpname[] = "sysprof-temp.XXXXXXXX";

    if (fd == -1) {
        fd = mkstemp(tmpname);
        if (fd == -1) err(1, "mkstemp");
    }

    return write(fd, src_buf, len);
}
