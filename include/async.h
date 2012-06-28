/*
 * Author: Ian Rose
 * Date Created: May 26, 2009
 *
 * Facilities for calling select() in a loop, plus simple event scheduling.
 */

#ifndef _ASYNC_H_
#define _ASYNC_H_

#include <stdio.h>
#include <sys/queue.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif 

/***************/
/*  CONSTANTS  */
/***************/

#define ASYNC_HIGH_PRIORITY 5
#define ASYNC_MEDIUM_PRIORITY 10
#define ASYNC_LOW_PRIORITY 15


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

typedef int (*async_io_check)(int, void*);
typedef void (*async_io_cb)(int, void*);
typedef void (*async_cb)(void*);

typedef struct async_evt_reg {
    struct timeval when;
    async_cb cb;
    void *user;
    u_char daemon;
    LIST_ENTRY(async_evt_reg) next;
} async_evt_reg;


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int async_add_fd(int fd, int priority, async_io_check readable, async_io_check writable,
    async_io_cb read, async_io_cb write, void *user);

#define async_add_read_fd(fd, priority, readable, read, user)           \
    async_add_fd(fd, priority, readable, NULL, read, NULL, user)

#define async_add_write_fd(fd, priority, writable, write, user)         \
    async_add_fd(fd, priority, NULL, writable, NULL, write, user)

inline void async_breakloop(void);

int async_cancel(async_evt_reg *evt);

void async_clear_events(void);

void async_clear_fds(void);

void async_dump_events(FILE * restrict stream);

void async_dump_fds(FILE * restrict stream);

int async_loop(void);

int async_remove_fd(int fd);

async_evt_reg *async_schedule(const struct timeval *dur, async_cb cb, void *user,
    int daemon);

async_evt_reg *async_schedule_abs(const struct timeval *when, async_cb cb,
    void *user, int daemon);

async_evt_reg *async_schedule_sec(u_int sec, async_cb cb, void *user,
    int daemon);

async_evt_reg *async_schedule_usec(u_long usec, async_cb cb, void *user,
    int daemon);

inline void async_set_timeout(struct timeval *timeout);

inline async_cb async_set_timeout_cb(async_cb cb, void *user);

int async_true_check(int fd, void *arg);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _ASYNC_H_ */
