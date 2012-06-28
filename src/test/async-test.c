/*
 * Author: Ian Rose
 * Date Created: May 26, 2009
 *
 * Tests async.c
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* local includes */
#include "async.h"

#define ASYNCLOOP()                                                     \
    do {                                                                \
        int rv = async_loop();                                          \
        if (rv == -1) {                                                 \
            warn("async_loop");                                         \
            abort();                                                    \
        } else if (rv == -2) {                                          \
            printf("    async_loop: async_breakloop called\n");         \
        } else {                                                        \
            printf("    async_loop: quit due to no fds/events\n");      \
        }                                                               \
    } while (0);                                                        \
    
static int count;

static int always_false(int fd, void *arg)
{
    return 0;
}

static int flip_flop(int fd, void *arg)
{
    return count & 1;
}

static void printstr_cb(void *arg)
{
    char *str = (char*)arg;
    printf("%s\n", str);
}

static void stopasync_cb(void *arg)
{
    async_breakloop();
}

static void timeout_cb(void *arg)
{
    printf("    timeout!\n");
    if (count == 5) async_breakloop();
    count++;
}

static void read_cb(int fd, void *arg)
{
    printf("    fd %d is readable\n", fd);
    if (count == 5) async_breakloop();
    count++;
}

static void write_cb(int fd, void *arg)
{
    printf("    fd %d is writable\n", fd);
    if (count == 5) async_breakloop();
    count++;
}

static void fail_cb(int fd, void *arg)
{
    assert(0  /* fail_cb */);
}

static void recurring_event(void *arg)
{
    u_long *lptr = (u_long*)arg;

    printf("    recurring_event is executing\n");
    count++;
    if (count < 5) async_schedule_usec(*lptr, recurring_event, arg, 0);
}

static void recurring_daemon_event(void *arg)
{
    u_long *lptr = (u_long*)arg;

    printf("    recurring_daemon_event is executing\n");
    count++;
    if (count < 5) async_schedule_usec(*lptr, recurring_event, arg, 1);
}

int main(int argc, char **argv)
{
    struct timeval timeout = { 0, 333*1000 };  /* 0.333 seconds */
    async_set_timeout(&timeout);
    async_set_timeout_cb(timeout_cb, NULL);

    int tube[2];
    if (pipe(tube) != 0)
        err(1, "pipe");

    count = 0;
    printf("\nstarting silent quit test\n");
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting timeout test\n");
    async_add_read_fd(tube[0], 5, async_true_check, fail_cb, NULL);
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting read test\n");
    async_add_read_fd(0, 10, async_true_check, read_cb, NULL);
    async_add_read_fd(1, 3, async_true_check, read_cb, NULL);
    async_add_read_fd(2, 5, async_true_check, read_cb, NULL);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    count = 0;
    printf("\nstarting read test without stdin\n");
    async_remove_fd(0);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting write test\n");
    async_add_write_fd(1, 5, async_true_check, write_cb, NULL);
    async_add_write_fd(2, 10, async_true_check, write_cb, NULL);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting write test with stdout/stderr priority flipped\n");
    async_add_write_fd(1, 10, async_true_check, write_cb, NULL);
    async_add_write_fd(2, 5, async_true_check, write_cb, NULL);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    count = 0;
    printf("\nstarting write test without stderr\n");
    async_remove_fd(2);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting write test with stdout/stderr at equal priority\n");
    async_add_write_fd(1, 10, async_true_check, write_cb, NULL);
    async_add_write_fd(2, 10, async_true_check, write_cb, NULL);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting read test with readable=false\n");
    async_add_read_fd(0, 10, always_false, read_cb, NULL);
    async_add_read_fd(1, 3, always_false, read_cb, NULL);
    async_add_read_fd(2, 5, always_false, read_cb, NULL);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();

    count = 0;
    printf("\nstarting read test with readable=[flip-flop]\n");
    async_add_read_fd(0, 10, flip_flop, read_cb, NULL);
    async_add_read_fd(1, 3, flip_flop, read_cb, NULL);
    async_add_read_fd(2, 5, flip_flop, read_cb, NULL);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();

    /* remove timeout handler to keep it from terminating async_loop */
    async_set_timeout(NULL);

    printf("\nstarting event test\n");
    struct timeval tv;
    gettimeofday(&tv, NULL);
    tv.tv_sec += 1;
    async_schedule_abs(&tv, printstr_cb, "    callback after 1 second...", 0);
    async_schedule_sec(2, printstr_cb, "    callback after 2 seconds...", 0);
    tv.tv_sec += 4;
    async_schedule_abs(&tv, printstr_cb, "    callback after 5 seconds...", 0);
    async_schedule_abs(&tv, stopasync_cb, NULL, 0);
    async_schedule_abs(&tv, printstr_cb, "    async_breakloop() was called, but I should still happen...", 0);
    tv.tv_sec += 1;
    async_schedule_abs(&tv, printstr_cb, "    I shouldn't be called (until round 2)...", 0);
    printf("events:\n");
    async_dump_events(stdout);
    ASYNCLOOP();

    printf("checking for leftover events\n");
    async_schedule_sec(1, stopasync_cb, NULL, 0);
    printf("events:\n");
    async_dump_events(stdout);
    ASYNCLOOP();

    async_clear_events();

    count = 0;
    printf("\nstarting event+fd test with readable=writable=[flip-flop]\n");
    gettimeofday(&tv, NULL);
    tv.tv_sec += 1;
    async_schedule_abs(&tv, printstr_cb, "    callback after 1 second...", 0);
    async_schedule_sec(1, printstr_cb, "    callback after 2 seconds...", 0);
    tv.tv_sec += 4;
    async_schedule_abs(&tv, printstr_cb, "    callback after 5 seconds...", 0);
    async_schedule_abs(&tv, stopasync_cb, NULL, 0);
    async_add_read_fd(0, 3, flip_flop, read_cb, NULL);
    async_add_fd(1, 5, flip_flop, flip_flop, read_cb, write_cb, NULL);
    async_add_fd(2, 10, flip_flop, flip_flop, read_cb, write_cb, NULL);
    printf("events:\n");
    async_dump_events(stdout);
    printf("fds:\n");
    async_dump_fds(stdout);
    ASYNCLOOP();

    async_clear_fds();
    async_clear_events();

    u_long interval = 100*1000;

    count = 0;
    printf("\nstarting recurring event tests (100ms)\n");
    async_schedule_usec(interval, recurring_event, &interval, 0);
    ASYNCLOOP();

    async_clear_events();

    count = 0;
    interval = 1000*1000;
    printf("\nstarting recurring event tests (1sec)\n");
    async_schedule_usec(interval, recurring_event, &interval, 0);
    ASYNCLOOP();

    async_clear_events();

    count = 0;
    interval = 1000*1000;
    u_long short_interval = 500*1000;
    printf("\nstarting recurring event tests (1sec) with a non-daemon event\n");
    async_schedule_usec(short_interval, recurring_daemon_event, &short_interval, 1);
    async_schedule_usec(interval, recurring_event, &interval, 0);
    ASYNCLOOP();

    async_clear_events();

    count = 0;
    interval = 10*1230*1000;
    printf("\nstarting recurring event tests (12.3sec)\n");
    async_schedule_usec(interval, recurring_event, &interval, 0);
    ASYNCLOOP();

    printf("tests complete\n");
}
