/*
 * Author: Ian Rose
 * Date Created: May 26, 2009
 *
 * Facilities for calling select() in a loop, plus simple event scheduling.
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/select.h>

/* local includes */
#include "async.h"

#define MILLION 1000000


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

LIST_HEAD(async_evt_reg_list, async_evt_reg);

struct async_fd_reg {
    int fd;
    int priority;
    async_io_check readable, writable;
    async_io_cb read, write;
    void *user;
    LIST_ENTRY(async_fd_reg) next;
};

LIST_HEAD(async_fd_reg_list, async_fd_reg);


/**********************/
/*  STATIC VARIABLES  */
/**********************/

// todo - replace with heap!
static struct async_evt_reg_list evt_list = 
    LIST_HEAD_INITIALIZER(evt_list);

static struct async_fd_reg_list fd_list = 
    LIST_HEAD_INITIALIZER(fd_list);

static async_cb timeout_cb = NULL;
static void *timeout_cb_arg = NULL;

static int timeout_isset = 0;
static struct timeval timeout_tv;

static int stop_flag = 0;  /* whether async_breakloop() has been called */
static int non_daemon_evt_count = 0;


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static int timeval_cmp(const struct timeval *a, const struct timeval *b);
static void timeval_subtract(const struct timeval *a, const struct timeval *b,
    struct timeval *result);


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

int
async_add_fd(int fd, int priority, async_io_check readable, async_io_check writable,
    async_io_cb read, async_io_cb write, void *user)
{
    struct async_fd_reg *reg = (struct async_fd_reg*)malloc(sizeof(struct async_fd_reg));
    if (reg == NULL) return -1;

    reg->fd = fd;
    reg->priority = priority;
    reg->readable = readable;
    reg->writable = writable;
    reg->read = read;
    reg->write = write;
    reg->user = user;

    if (LIST_EMPTY(&fd_list)) {
        LIST_INSERT_HEAD(&fd_list, reg, next);
        return 0;
    }

    struct async_fd_reg *elt, *last;
    LIST_FOREACH(elt, &fd_list, next) {
        last = elt;

        if (elt->priority > priority) {
            /* new fd-reg should be inserted right before this elt */
            LIST_INSERT_BEFORE(elt, reg, next);
            return 0;
        }
    }

    /* new fd-reg belongs at the end of the list */
    LIST_INSERT_AFTER(last, reg, next);
    return 0;
}

inline void
async_breakloop(void)
{
    stop_flag = 1;
}

int
async_cancel(async_evt_reg *evt)
{
    struct async_evt_reg *elt;
    LIST_FOREACH(elt, &evt_list, next) {
        if (elt == evt) {
            LIST_REMOVE(elt, next);
            free(elt);
            return 0;
        }
    }
    errno = EINVAL;
    return -1;
}

void
async_clear_events(void)
{
    struct async_evt_reg *evt;
    while (!LIST_EMPTY(&evt_list)) {
        evt = LIST_FIRST(&evt_list);
        if (!evt->daemon) non_daemon_evt_count--;
        LIST_REMOVE(evt, next);
        free(evt);
    }
    
    assert(non_daemon_evt_count == 0);
}

void
async_clear_fds(void)
{
    struct async_fd_reg *elt;
    while (!LIST_EMPTY(&fd_list)) {
        elt = LIST_FIRST(&fd_list);
        LIST_REMOVE(elt, next);
        free(elt);
    }
}

void
async_dump_events(FILE * restrict stream)
{
    struct async_evt_reg *elt;
    LIST_FOREACH(elt, &evt_list, next) {
        fprintf(stream, "%d.%06ld\n", elt->when.tv_sec, elt->when.tv_usec);
    }
}

void
async_dump_fds(FILE * restrict stream)
{
    struct async_fd_reg *elt;
    LIST_FOREACH(elt, &fd_list, next) {
        fprintf(stream, "%d %d\n", elt->fd, elt->priority);
    }
}

int
async_loop(void)
{
    fd_set zeroset;
    FD_ZERO(&zeroset);

    while (1) {
        /* check for an async_stop() call */
        if (stop_flag == 1) {
            stop_flag = 0;
            return -2;
        }

        struct timeval next_evt_delay = {0, 0};
        int events_are_pending = 0;

        /* check event list */
        if (! LIST_EMPTY(&evt_list)) {
            struct timeval now;
            gettimeofday(&now, NULL);
            while (!LIST_EMPTY(&evt_list)) {
                struct async_evt_reg *evt = LIST_FIRST(&evt_list);
                if (timeval_cmp(&evt->when, &now) > 0) {
                    timeval_subtract(&evt->when, &now, &next_evt_delay);
                    events_are_pending = 1;
                    break;
                }
                evt->cb(evt->user);
                if (!evt->daemon) non_daemon_evt_count--;
                LIST_REMOVE(evt, next);
                free(evt);
            }
        }

        fd_set readset = zeroset;
        fd_set writeset = zeroset;

        int max_fd = -1;
        struct async_fd_reg *elt;
        LIST_FOREACH(elt, &fd_list, next) {
            int added = 0;
            if ((elt->readable != NULL) && elt->readable(elt->fd, elt->user)) {
                FD_SET(elt->fd, &readset);
                added = 1;
            }
            if ((elt->writable != NULL) && elt->writable(elt->fd, elt->user)) {
                FD_SET(elt->fd, &writeset);
                added = 1;
            }
            if (added && (elt->fd > max_fd))
                max_fd = elt->fd;
        }

        struct timeval tv = timeout_tv;
        struct timeval *timeout = &tv;

        if (timeout_isset) {
            if (events_are_pending) {
                if (timeval_cmp(&next_evt_delay, &timeout_tv) < 0) {
                    timeout = &next_evt_delay;
                }
            }
        } else {
            if (events_are_pending)
                timeout = &next_evt_delay;
            else
                timeout = NULL;
        }

        if (LIST_EMPTY(&fd_list) && (non_daemon_evt_count == 0)) {
            /* no (non-daemon) events and no file descriptors - quit */
            return 0;
        }

        int rv = select(max_fd+1, &readset, &writeset, NULL, timeout);
        int found = 0;
        int priority = 0;

        switch (rv) {
        case 0:
            /* timeout */

            /* if an event is due, don't call the timeout handler */
            if (timeout != &next_evt_delay) {
                if (timeout_cb != NULL)
                    timeout_cb(timeout_cb_arg);
            }
            break;
        case -1:
            if (errno == EINTR) continue;  /* ignore EINTR */
            return -1;
        default:  /* at least one file descriptor is ready */
            LIST_FOREACH(elt, &fd_list, next) {
                /*
                 * Once a file descriptor is found that is ready for I/O, we
                 * handle that file descriptor plus all others at the same
                 * priority level, and then break, skipping all file descriptors
                 * at weaker priority levels.
                 */
                if (found) {
                    if (elt->priority > priority)
                        break;
                }

                /*
                 * Always check and handle reads before writes; when a TCP
                 * connection breaks, reads on the socket fail nicely (return -1
                 * and set errno) whereas writes on the socket cause a SIGPIPE.
                 */
                if (FD_ISSET(elt->fd, &readset)) {
                    elt->read(elt->fd, elt->user);
                    found = 1;
                    priority = elt->priority;
                }

                if ((elt->write != NULL) && FD_ISSET(elt->fd, &writeset)) {
                    elt->write(elt->fd, elt->user);
                    found = 1;
                    priority = elt->priority;
                }
            }
        }
    }
}

int
async_remove_fd(int fd)
{
    struct async_fd_reg *elt;
    LIST_FOREACH(elt, &fd_list, next) {
        if (elt->fd == fd) {
            /* found it */
            LIST_REMOVE(elt, next);
            free(elt);
            return 0;
        }
    }

    /* fd not found in list */
    errno = EINVAL;
    return -1;
}

async_evt_reg *async_schedule(const struct timeval *dur, async_cb cb, void *user,
    int daemon)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        return NULL;

    tv.tv_sec += dur->tv_sec;
    tv.tv_usec += dur->tv_usec;
    if (tv.tv_usec > MILLION) {
        tv.tv_sec ++;
        tv.tv_usec -= MILLION;
    }
    return async_schedule_abs(&tv, cb, user, daemon);
}

async_evt_reg *async_schedule_abs(const struct timeval *when, async_cb cb,
    void *user, int daemon)
{
    struct async_evt_reg *reg = (struct async_evt_reg*)
        malloc(sizeof(struct async_evt_reg));
    if (reg == NULL) return NULL;

    reg->when = *when;
    reg->cb = cb;
    reg->user = user;
    reg->daemon = daemon;

    if (!daemon) non_daemon_evt_count++;

    if (LIST_EMPTY(&evt_list)) {
        LIST_INSERT_HEAD(&evt_list, reg, next);
        return reg;
    } else {
        struct async_evt_reg *elt, *last;
        LIST_FOREACH(elt, &evt_list, next) {
            last = elt;

            if (timeval_cmp(&reg->when, &elt->when) < 0) {
                /* new event-reg should be inserted right before this elt */
                LIST_INSERT_BEFORE(elt, reg, next);
                return reg;
            }
        }

        /* new event-reg belongs at the end of the list */
        LIST_INSERT_AFTER(last, reg, next);
        return reg;
    }

    assert(0  /* not reached */);
}

async_evt_reg *async_schedule_sec(u_int sec, async_cb cb, void *user, int daemon)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        return NULL;

    tv.tv_sec += sec;
    return async_schedule_abs(&tv, cb, user, daemon);
}

async_evt_reg *async_schedule_usec(u_long usec, async_cb cb, void *user,
    int daemon)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        return NULL;

    int secs = usec / MILLION;
    usec -= secs*MILLION;

    if ((tv.tv_usec + usec) > MILLION) {
        tv.tv_sec += secs + 1;
        tv.tv_usec += usec - MILLION;
    } else {
        tv.tv_sec += secs;
        tv.tv_usec += usec;
    }
    return async_schedule_abs(&tv, cb, user, daemon);
}

inline void
async_set_timeout(struct timeval *timeout)
{
    if (timeout == NULL) {
        timeout_isset = 0;
    } else {
        timeout_isset = 1;
        timeout_tv = *timeout;
    }
}

inline async_cb
async_set_timeout_cb(async_cb cb, void *user)
{
    async_cb old = timeout_cb;
    timeout_cb = cb;
    timeout_cb_arg = user;
    return old;
}

int
async_true_check(int fd, void *arg)
{
    return 1;
}


/********************/
/*  STATIC METHODS  */
/********************/

static int
timeval_cmp(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec < b->tv_sec)
        return -1;
    if (a->tv_sec > b->tv_sec)
        return 1;
    /* a->tv_sec == b->tv-sec */
    if (a->tv_usec < b->tv_usec)
        return -1;
    if (a->tv_usec > b->tv_usec)
        return 1;
    /* a->tv_usec == b->tv_usec */
    return 0;
}

static void
timeval_subtract(const struct timeval *a, const struct timeval *b,
    struct timeval *result)
{
    if (a->tv_usec >= b->tv_usec) {
        result->tv_sec = a->tv_sec - b->tv_sec;
        result->tv_usec = a->tv_usec - b->tv_usec;
    } else {
        result->tv_sec = a->tv_sec - b->tv_sec - 1;
        result->tv_usec = MILLION + a->tv_usec - b->tv_usec;
    }
}
