/*
 * Author: Ian Rose
 * Date Created: May 25, 2009
 *
 * Implements the Argos network protocol.
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

/* local includes */
#include "async.h"
#include "buffer.h"
#include "orion/log.h"
#include "orion/time.h"
#include "argos/net.h"
#include "argos/sniffer.h"


/***************/
/*  CONSTANTS  */
/***************/

/* we try to pass at least this much data each time we call send() */
#define SEND_SOFT_MIN       (32*1024)   /* 32 KB */

/* compression is only performed if at least this much data is available */
#define COMPRESS_HARD_MIN   (32*1024)   /* 32 KB */

/*
 * long compressions are bad because they can starve other events (like reading
 * from pcap descriptors; try to avoid this by limiting the number of bytes that
 * we will try to compress at one time
 */
#define COMPRESS_HARD_MAX (1024*1024)  /* 1 MB */

/* if this much time elapses between compressions, ignore COMPRESS_HARD_MIN */
#define COMPRESS_DELAY_MAX  { 1, 0 }    /* struct timeval initializer */


#define IS_NETWORK_ERROR(err) ((errno == EHOSTUNREACH) ||      \
        (errno == ECONNREFUSED) ||                             \
        (errno == ECONNRESET) ||                               \
        (errno == EHOSTDOWN) ||                                \
        (errno == ENETDOWN) ||                                 \
        (errno == ETIMEDOUT) ||                                \
        (errno == EPIPE))                                      \

#define KABOOM(s)                                                     \
    do {                                                              \
        orion_log_crit("%s at line %d of %s in file %s", s, __LINE__, \
            __func__, __FILE__);                                      \
        orion_log_flush();                                            \
        warn("%s at line %d of %s in file %s", s, __LINE__, __func__, \
            __FILE__);                                                \
        abort();                                                      \
    } while (0);                                                      \

#ifndef min
#define min(a,b) (a < b ? a : b)
#endif
    

/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static int attempt_connect(struct argos_net_conn *conn);
inline static int buffers_are_empty(const struct argos_net_conn *conn);
static void close_socket(int fd);
static int compress_and_xfer(struct argos_net_conn *conn, u_char force);
static void compression_timeout(void *arg);
static void handle_connect(struct argos_net_conn *conn);
static void handle_connect_success(struct argos_net_conn *conn);
static int handle_connect_failure(struct argos_net_conn *conn);
static void kill_connection(struct argos_net_conn *conn);
static void process_inbuf(struct argos_net_conn *conn);
static void reconnect_event(void *arg);
static void reset_connection(struct argos_net_conn *conn, int flush_buffers);
static ssize_t socket_send(struct argos_net_conn *conn, const void *msg, size_t len);

/* async callbacks */
static int readable_cb(int fd, void *arg);
static int writable_cb(int fd, void *arg);
static void read_cb(int fd, void *arg);
static void write_cb(int fd, void *arg);


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

void
argos_net_close(struct argos_net_conn *conn)
{
    orion_log_func();

    if (conn->state != ARGOS_NET_CONN_DEAD)
        kill_connection(conn);

    buffer_destroy(conn->inbuf);
    buffer_destroy(conn->outbuf);
    buffer_destroy(conn->pktbuf);
    free(conn);
}

struct argos_net_conn *
argos_net_client_create(struct sockaddr_in *remote_addr, int dlt,
    const struct sockaddr_in *client_ip, size_t inbufsz, size_t outbufsz,
    size_t pktbufsz)
{
    if (dlt < 0) {
        errno = EINVAL;
        return NULL;
    }

    /* inbufsz has to at least be big enough to hold a handshake message */
    if (inbufsz < sizeof(struct argos_net_handshake_msg)) {
        errno = ENOSPC;
        return NULL;
    }

    struct argos_net_conn *conn = malloc(sizeof(struct argos_net_conn));
    if (conn == NULL) return NULL;
    bzero(conn, sizeof(struct argos_net_conn));

    conn->dlt = dlt;
    conn->state = ARGOS_NET_CONN_IDLE;
    memcpy(&conn->remote_addr, remote_addr, sizeof(struct sockaddr_in));
    conn->init_backoff = ARGOS_NET_DEF_INIT_BACKOFF;
    conn->max_backoff = ARGOS_NET_DEF_MAX_BACKOFF;
    conn->cur_backoff = conn->init_backoff;
    conn->inbuf = buffer_create(inbufsz);
    if (conn->inbuf == NULL) goto fail;
    conn->outbuf = buffer_create(outbufsz);
    if (conn->outbuf == NULL) goto fail;
    conn->pktbuf = buffer_create(pktbufsz);
    if (conn->pktbuf == NULL) goto fail;

    /* outbuf and pktbuf should be empty! */
    assert(buffer_len(conn->outbuf) == 0);
    assert(buffer_len(conn->pktbuf) == 0);

    conn->handshake.msgtype = htons(ARGOS_NET_HANDSHAKE_MSGTYPE);
    conn->handshake.msglen = htonl(sizeof(struct argos_net_handshake_msg));
    conn->handshake.magicnum = htonl(ARGOS_NET_MAGICNUM);
    conn->handshake.major_version = htons(ARGOS_MAJOR_VERSION);
    conn->handshake.minor_version = htons(ARGOS_MINOR_VERSION);
    conn->handshake.dlt = htonl(conn->dlt);
    if (client_ip != NULL)
        conn->handshake.ip = client_ip->sin_addr.s_addr;

    /* start trying to connect */
    attempt_connect(conn);

    return conn;

 fail:
    if (conn->inbuf != NULL) buffer_destroy(conn->inbuf);
    if (conn->outbuf != NULL) buffer_destroy(conn->outbuf);
    if (conn->pktbuf != NULL) buffer_destroy(conn->pktbuf);
    free(conn);
    return NULL;
}

int
argos_net_init(void)
{
#if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_LZO
    /* initialize the LZO library; this should be done only once */
    if (lzo_init() != LZO_E_OK) {
        errno = EFAULT;
        return -1;
    }
#endif
    return 0;
}

int
argos_net_is_connected(const struct argos_net_conn *conn)
{
    return conn->state == ARGOS_NET_CONN_CONNECTED;
}

size_t
argos_net_queue_room(const struct argos_net_conn *conn)
{
    return buffer_remaining(conn->pktbuf);
}

void
argos_net_shutdown(struct argos_net_conn *conn)
{
    if (conn->shutdown == 0) {
        conn->shutdown = 1;
        if (buffers_are_empty(conn))
            kill_connection(conn);
    }
}

ssize_t
argos_net_send_errmsg(struct argos_net_conn *conn, uint16_t errnum,
    const char *errmsg)
{
    if (conn->state == ARGOS_NET_CONN_DEAD) {
        orion_log_err("unable to send on DEAD network handle");
        errno = EBADF;
        return -1;
    }

    if (conn->shutdown) {
        /* illegal to try to send after argos_net_shutdown() is called */
        errno = EPIPE;
        return -1;
    }

    int slen = strlen(errmsg);
    if (slen > (1 << 16)) {
        errno = EMSGSIZE;
        return -1;
    }

    struct argos_net_error_msg msg;
    msg.msgtype = htons(ARGOS_NET_ERROR_MSGTYPE);
    msg.msglen = htonl(sizeof(struct argos_net_error_msg) + slen);
    msg.errnum = htons(errnum);

    /* error messages enqueue directly into the outbuf */
    size_t reqlen = sizeof(msg) + slen;
    if (buffer_remaining(conn->outbuf) < reqlen) {
        errno = ENOBUFS;
        return -1;
    }

    int rv = buffer_write(conn->outbuf, &msg, sizeof(msg));
    assert(rv >= 0);

    rv = buffer_write(conn->outbuf, errmsg, slen);
    assert(rv >= 0);

    return reqlen;
}

ssize_t
argos_net_send_packet(struct argos_net_conn *conn, const struct pcap_pkthdr *h,
    const u_char *sp, uint8_t channel)
{
    if (conn->state == ARGOS_NET_CONN_DEAD) {
        orion_log_err("unable to send on DEAD network handle");
        errno = EBADF;
        return -1;
    }

    assert(conn->state != ARGOS_NET_CONN_IDLE);

    if (conn->shutdown) {
        /* illegal to try to send after argos_net_shutdown() is called */
        errno = EPIPE;
        return -1;
    }

    struct argos_net_pcap_msg msg;
    size_t reqlen = sizeof(msg) + h->caplen;

    msg.msgtype = htons(ARGOS_NET_PCAP_MSGTYPE);
    msg.msglen = htonl(reqlen);
    msg.channel = channel;
    msg.ts_sec = htonl(h->ts.tv_sec);
    msg.ts_usec = htonl(h->ts.tv_usec);
    msg.msglen = htonl(reqlen);
    msg.pktlen = htonl(h->len);
    msg.caplen = htonl(h->caplen);

    if (buffer_remaining(conn->pktbuf) < reqlen) {
        errno = ENOBUFS;
        return -1;
    }

    int rv = buffer_write(conn->pktbuf, &msg, sizeof(msg));
    assert(rv >= 0);

    rv = buffer_write(conn->pktbuf, sp, h->caplen);
    assert(rv >= 0);

    if (conn->compress_evt_reg == NULL) {
        static const struct timeval timeout = COMPRESS_DELAY_MAX;
        conn->compress_evt_reg = async_schedule(&timeout, compression_timeout,
            conn, 0);
    }

    return reqlen;
}

ssize_t
argos_net_send_stats(struct argos_net_conn *conn,
    const struct argos_net_stats *stats)
{
    if (conn->state == ARGOS_NET_CONN_DEAD) {
        orion_log_err("unable to send on DEAD network handle");
        errno = EBADF;
        return -1;
    }

    assert(conn->state != ARGOS_NET_CONN_IDLE);

    if (conn->shutdown) {
        /* illegal to try to send after argos_net_shutdown() is called */
        errno = EPIPE;
        return -1;
    }

    float usr_perc =
        (stats->usr_time.tv_sec*1000 + (stats->usr_time.tv_usec+500)/1000) /
        (float)stats->duration_ms;
    float sys_perc =
        (stats->sys_time.tv_sec*1000 + (stats->sys_time.tv_usec+500)/1000) /
        (float)stats->duration_ms;

    orion_log_info("STATS: kern_recv=%u kern_drop=%u app_recv=%u cpu_sys=%.2f"
        " cpu_usr=%.2f maxrss_mb=%.1f send_byterate=%d",
        stats->kern_recv, stats->kern_drop, stats->app_recv, sys_perc,
        usr_perc, stats->maxrss_kbytes/(float)1024,
        (conn->bytes_sent*1000/stats->duration_ms));

    struct argos_net_stats_msg msg;
    msg.msgtype = htons(ARGOS_NET_STATS_MSGTYPE);
    msg.msglen = htonl(sizeof(msg));
    msg.flags = htons(conn->status_flags);
    msg.ts_sec = htonl(stats->ts.tv_sec);
    msg.ts_usec = htonl(stats->ts.tv_usec);
    msg.duration_ms = htonl(stats->duration_ms);
    msg.kern_recv = htonl(stats->kern_recv);
    msg.kern_drop = htonl(stats->kern_drop);
    msg.app_recv = htonl(stats->app_recv);
    msg.usr_time_ms = htonl(stats->usr_time.tv_sec*1000 + (stats->usr_time.tv_usec+500)/1000);
    msg.sys_time_ms = htonl(stats->sys_time.tv_sec*1000 + (stats->sys_time.tv_usec+500)/1000);
    msg.maxrss_kbytes = htonl(stats->maxrss_kbytes);
    msg.net_sent_bytes = htonl(conn->bytes_sent);
    msg.pcap_opened_sec = htonl(stats->pcap_opened.tv_sec);
    msg.pcap_opened_usec = htonl(stats->pcap_opened.tv_sec);

    /* stats messages enqueue directly into the outbuf */
    int rv = buffer_write(conn->outbuf, &msg, sizeof(msg));
    if (rv == -1) {
        errno = ENOBUFS;
        return -1;
    }

    /* reset status flags and bytes sent/recv */
    conn->bytes_sent = 0;
    conn->bytes_recv = 0;
    if (conn->state == ARGOS_NET_CONN_CONNECTED)
        conn->status_flags = ARGOS_NET_STATS_CONN_UP;
    else
        conn->status_flags = ARGOS_NET_STATS_CONN_DOWN;

    return sizeof(msg);
}

void
argos_net_set_connect_backoffs(struct argos_net_conn *conn,
    time_t initial_backoff, time_t max_backoff)
{
    conn->init_backoff = initial_backoff;
    conn->max_backoff = max_backoff;
}

argos_net_strhandler
argos_net_set_bpfhandler(struct argos_net_conn *conn,
    argos_net_strhandler handler, void *user)
{
    argos_net_strhandler tmp = conn->bpfhandler;
    conn->bpfhandler = handler;
    conn->bpfhandler_user = user;
    return tmp;
}

argos_net_basichandler
argos_net_set_breakhandler(struct argos_net_conn *conn,
    argos_net_basichandler handler, void *user)
{
    argos_net_basichandler tmp = conn->breakhandler;
    conn->breakhandler = handler;
    conn->breakhandler_user = user;
    return tmp;
}

argos_net_chanhandler
argos_net_set_chanhandler(struct argos_net_conn *conn,
    argos_net_chanhandler handler, void *user)
{
    argos_net_chanhandler tmp = conn->chanhandler;
    conn->chanhandler = handler;
    conn->chanhandler_user = user;
    return tmp;
}

argos_net_strhandler
argos_net_set_clickhandler(struct argos_net_conn *conn,
    argos_net_strhandler handler, void *user)
{
    argos_net_strhandler tmp = conn->clickhandler;
    conn->clickhandler = handler;
    conn->clickhandler_user = user;
    return tmp;
}

argos_net_basichandler
argos_net_set_connecthandler(struct argos_net_conn *conn,
    argos_net_basichandler handler, void *user)
{
    argos_net_basichandler tmp = conn->connecthandler;
    conn->connecthandler = handler;
    conn->connecthandler_user = user;
    return tmp;
}

argos_net_errhandler
argos_net_set_errhandler(struct argos_net_conn *conn,
    argos_net_errhandler handler, void *user)
{
    argos_net_errhandler tmp = conn->errhandler;
    conn->errhandler = handler;
    conn->errhandler_user = user;
    return tmp;
}

argos_net_pkthandler
argos_net_set_pkthandler(struct argos_net_conn *conn,
    argos_net_pkthandler handler, void *user)
{
    argos_net_pkthandler tmp = conn->pkthandler;
    conn->pkthandler = handler;
    conn->pkthandler_user = user;
    return tmp;
}


/********************/
/*  STATIC METHODS  */
/********************/

static int
attempt_connect(struct argos_net_conn *conn)
{
    if (!conn->connect_failed)
        orion_log_func();

    assert(conn->state == ARGOS_NET_CONN_IDLE);

    /* create and set up the actual socket */
    conn->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->sock < 0) {
        orion_log_errno("socket");
        goto fail;
    }

    /* set non-blocking on socket */
    int status = fcntl(conn->sock, F_GETFL, NULL);
    if (status < 0) {
        orion_log_crit_errno("fcntl(F_GETFL)");
        goto fail;
    }

    status |= O_NONBLOCK;

    if (fcntl(conn->sock, F_SETFL, status) < 0) {
        orion_log_crit_errno("fcntl(F_SETFL)");
        goto fail;
    }

    /* prevent socket from throwing SIGPIPE signals */
    int on = 1;
    if (setsockopt(conn->sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&on,
            sizeof(on)) < 0) {
        orion_log_crit_errno("setsockopt(SO_NOSIGPIPE)");
        goto fail;
    }

    /* select for writes (that's how completion of a connect() is signaled) */
    int rv = async_add_write_fd(conn->sock, ARGOS_NET_CONNECT_ASYNCPRIO,
        writable_cb, write_cb, conn);
    if (rv != 0) {
        orion_log_errno("async_add_write_fd");
        async_remove_fd(conn->sock);
        goto fail;
    }

    /* finally ready to attempt the connect() call */
    rv = connect(conn->sock, (struct sockaddr*)&conn->remote_addr,
        sizeof(conn->remote_addr));

    if (rv == -1)
        return handle_connect_failure(conn);
    
    /* else, rv=0 which means instant success (odd...) */
    orion_log_info("connect() succeeded immediately");
    handle_connect_success(conn);
    return 0;

 fail:
    /* 
     * something very bad happened; presumably either there is a code bug or the
     * OS is in bad shape (e.g. out of memory, no more file descriptors, etc.)
     */
    kill_connection(conn);
    orion_log_crit("failed to create network client");
    return -1;
}

inline static int
buffers_are_empty(const struct argos_net_conn *conn)
{
    return (buffer_len(conn->outbuf) == 0) && (buffer_len(conn->pktbuf) == 0);
}

static void
close_socket(int fd)
{
    /* remove connect/write registration */
    if (async_remove_fd(fd) != 0)
        orion_log_crit_errno("async_remove_fd");

    /* remove read registration (there may not be one if we didn't connect yet */
    (void) async_remove_fd(fd);

    do {
        if (close(fd) == -1) {
            if (errno == EINTR)
                continue;
            else
                orion_log_errno("close");
        }
    } while (0);
}

static int
compress_and_xfer(struct argos_net_conn *conn, u_char force)
{
    /*
     * if the packet-buf is empty, quit right off; this check is not necessary
     * for correctness, but its nice to check it early for efficiency and also
     * to avoid some spam in the logs (e.g. lots of 'compression timeout'
     * messages) since this case is quite common.
     */
    if (buffer_len(conn->pktbuf) == 0)
        return 0;

#if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_NONE
    size_t to_xfer = min(buffer_len(conn->pktbuf),
        buffer_remaining(conn->outbuf));

    if (to_xfer == 0) return 0;

#if ARGOS_NET_TRACE_IO
    struct timeval start;
    if (gettimeofday(&start, NULL) != 0) {
        orion_log_crit_errno("gettimeofday");
        return 0;
    }
#endif /* #if ARGOS_NET_TRACE_IO */
    
    memcpy(buffer_tail(conn->outbuf), buffer_head(conn->pktbuf), to_xfer);

#if ARGOS_NET_TRACE_IO
    struct timeval end;
    if (gettimeofday(&end, NULL) != 0) {
        orion_log_crit_errno("gettimeofday");
        return 0;
    }

    struct timeval elapsed;
    orion_time_subtract(&end, &start, &elapsed);

    float elapsed_msec = elapsed.tv_sec*1000 + (float)elapsed.tv_usec/1000;

    orion_log_debug("memcpy'ed %u bytes in %.2f ms (%.2f MB/s)",
        to_xfer, elapsed_msec, ((to_xfer/elapsed_msec)*1000)/(1024*1024));
#endif /* #if ARGOS_NET_TRACE_IO */

    if (buffer_expand(conn->outbuf, to_xfer) < 0)
        KABOOM("buffer_expand");

    if (buffer_discard(conn->pktbuf, to_xfer) < 0)
        KABOOM("buffer_discard");

#else  /* #if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_NONE  */

    /*
     * In general, we want large blocks of packets to compress (because that
     * makes the compression more space-efficient).  So if there isn't much data
     * in pktbuf, just return without doing anything.  Note that we also need to
     * check to make sure there is enough room in the outbuf for us to put the
     * packets once they are compressed.
     */
    size_t minlen;

    if (force) {
        minlen = 1;
    } else {
        /*
         * If this conn has a small pktbuf (such that even with totally full,
         * the COMPRESS_HARD_MIN won't be met), then we need to adjust to a
         * limit that is actually attainable; we use 75% of the buffer size.
         */
        minlen = (3*buffer_size(conn->pktbuf))/4;

        /* usually, this is the value that we end up with for minlen: */
        minlen = min(minlen, COMPRESS_HARD_MIN);

        /*
         * one more special case: if argos_net_shutdown() was called on this
         * connection then there is no minimum compression size - we just want
         * to drain the buffers no matter how much is in there
         */
        if (conn->shutdown) minlen = 1;
    }

    /* quit if we don't have at least 'minlen' bytes of packet data to compress */
    if (buffer_len(conn->pktbuf) < minlen)
        return 0;

    /* check the total space available in the connection outbuf */
    size_t total_space = buffer_remaining(conn->outbuf);
    if (total_space < sizeof(struct argos_net_compress_msg))
        return 0;  /* not enough space available */

    /* this is the total space available for the compressed data */
    size_t space = total_space - sizeof(struct argos_net_compress_msg);

    /* don't exceed the maximum compression-block size */
    space = min(space, ARGOS_NET_MAX_COMPRESS_LEN);

    /*
     * given the space available, calculate how much packet data we can safely
     * consume (considering worst-cast input:output size ratios for whatever
     * compression algorithm we are using).
     */
    ssize_t ok_to_consume;

#if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_LZO
    /* this is the inversion of the function given in the LZO faq file */
    ok_to_consume = (16*(space - 64 - 3))/17;
#elif ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_QUICKLZ
    /* this is the inversion of the function given in the QuickLZ manual */
    ok_to_consume = space - 400;
#else
    #error "unknown value for ARGOS_NET_USE_COMPRESSION"
#endif

    if (ok_to_consume <= 0) return 0;  /* not enough space available */

    /* number of bytes that will actually be compressed and transferred */
    size_t readlen = min(ok_to_consume, buffer_len(conn->pktbuf));
    assert(readlen > 0);

    /* don't exceed the maximum compression-block size */
    readlen = min(readlen, COMPRESS_HARD_MAX);

    /* where the compressed data should be written */
    u_char *write_ptr = buffer_tail(conn->outbuf) +
        sizeof(struct argos_net_compress_msg);

    struct argos_net_compress_msg *msg =
        (struct argos_net_compress_msg*)buffer_tail(conn->outbuf);
    msg->msgtype = htons(ARGOS_NET_COMPRESS_MSGTYPE);
    /* have to defer filling in msglen field */
    msg->algorithm = ARGOS_NET_USE_COMPRESSION;
    msg->orig_len = htonl(readlen);

#if ARGOS_NET_TRACE_IO
    /* measure the elapsed process time to try to detect cpu starvation */
    struct itimerval itimer_start;
    bzero(&itimer_start, sizeof(itimer_start));
    itimer_start.it_value.tv_sec = 100;  /* arbitrary large value */

    struct timeval start;
    if (gettimeofday(&start, NULL) != 0) {
        orion_log_crit_errno("gettimeofday");
        return 0;
    }

    if (setitimer(ITIMER_PROF, &itimer_start, NULL) != 0) {
        orion_log_crit_errno("setitimer");
        return 0;
    }
#endif /* #if ARGOS_NET_TRACE_IO */

#if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_LZO
    lzo_uint lzo_outlen;
    int rv = lzo1x_1_compress(buffer_head(conn->pktbuf), readlen,
        write_ptr, &lzo_outlen, conn->lzo_wrk_space);
    if (rv != LZO_E_OK) {
        /* according to LZO documentation "this should NEVER happen" */
        orion_log_crit("LZO compression library internal error: %d", rv);
        return 0;
    }

    uint32_t outlen = lzo_outlen;

#elif ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_QUICKLZ
    uint32_t outlen = qlz_compress(buffer_head(conn->pktbuf), (char*)write_ptr, readlen, conn->qlz_scratch);
#else
    #error "unknown value for ARGOS_NET_USE_COMPRESSION"
#endif

#if ARGOS_NET_TRACE_IO
    /* call this before gettimeofday */
    struct itimerval itimer_end;
    if (getitimer(ITIMER_PROF, &itimer_end) != 0) {
        orion_log_crit_errno("getitimer");
        return 0;
    }
#endif /* #if ARGOS_NET_TRACE_IO */

    struct timeval end;
    if (gettimeofday(&end, NULL) != 0) {
        orion_log_crit_errno("gettimeofday");
        return 0;
    }

#if ARGOS_NET_TRACE_IO
    struct timeval real_elapsed;
    orion_time_subtract(&end, &start, &real_elapsed);

    float real_msec = real_elapsed.tv_sec*1000 +
        (float)real_elapsed.tv_usec/1000;

    struct timeval process_elapsed;
    orion_time_subtract(&itimer_start.it_value, &itimer_end.it_value,
        &process_elapsed);

    float process_msec = process_elapsed.tv_sec*1000 +
        (float)process_elapsed.tv_usec/1000;

    orion_log_debug("compressed %u bytes to %u (%.2f%%) in %.2f ms"
        " (%.2f MB/s); %.2f ms process time", readlen, outlen,
        (float)outlen*100/readlen, real_msec,
        ((readlen/real_msec)*1000)/(1024*1024), process_msec);
#endif /* #if ARGOS_NET_TRACE_IO */

    size_t total_len = sizeof(struct argos_net_compress_msg) + outlen;
    if (buffer_expand(conn->outbuf, total_len) < 0)
        KABOOM("buffer_expand");

    if (buffer_discard(conn->pktbuf, readlen) < 0)
        KABOOM("buffer_discard");

    /* write back into the msglen field now that we know the total length */
    msg->msglen = htonl(sizeof(struct argos_net_compress_msg) + outlen);

    /* check for incompressible block (this is normal for small blocks) */
    if (outlen > readlen) {
        if (readlen < 4096)
            orion_log_debug("incompressible block: inlen=%d, outlen=%d", readlen,
                outlen);
        else
            orion_log_warn("incompressible block: inlen=%d, outlen=%d", readlen,
                outlen);
    }
#endif  /* #if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_NONE  */

    /* cancel any currently schedule compression timeout event */
    if (conn->compress_evt_reg != NULL) {
        if (async_cancel(conn->compress_evt_reg) != 0)
            orion_log_crit_errno("async_cancel");
        conn->compress_evt_reg = NULL;
    }

    return 1;
}

static void
compression_timeout(void *arg)
{
    struct argos_net_conn *conn = arg;
    conn->compress_evt_reg = NULL;

    orion_log_debug("compression timeout");

    /*
     * When this event is fired, it means that too much time has elapsed since
     * the last compression, so we call compress_and_xfer() with force=1 so that
     * the (normal) minimum compression size will be ignored.  This mechanism is
     * to handle low-traffic situations where otherwise we might wait
     * excessively long for enough data to accumulate before compressing
     * (because we are trying to be efficient).
     */
    (void) compress_and_xfer(conn, 1 /* force */);
}

static void
handle_connect(struct argos_net_conn *conn)
{
    assert(conn->state == ARGOS_NET_CONN_CONNECTING);

    /*
     * connect() completed, but did it succeed or fail?  getpeername() will
     * tell us.  reference: http://cr.yp.to/docs/connect.html
     */
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    if (getpeername(conn->sock, (struct sockaddr*)&sin, &slen) == -1) {
        if (errno == ENOTCONN) {
            /* connect failed; ok now use error slippage to get the real error */
            char c;
            int rv = read(conn->sock, &c, 1);
            assert(rv == -1);
            handle_connect_failure(conn);
        } else if (errno == ECONNRESET) {
            /* 
             * not sure if this can actually happen - perhaps with perfect
             * timing (connection lost right before we call getpeername)
             */
            orion_log_warn_errno("getpeername");
            reset_connection(conn, 0);
        } else {
            /* this is unexpected... */
            orion_log_crit_errno("getpeername");
            kill_connection(conn);
            orion_log_crit("unexpected getpeername() error after asynchronous"
                " connect() selected for writability; connection is now dead");
        }
    } else {
        /* connect succeeded */
        orion_log_info("connect() succeeded asynchronously");
        handle_connect_success(conn);
    }
}

static void
handle_connect_success(struct argos_net_conn *conn)
{
    conn->state = ARGOS_NET_CONN_CONNECTED;
    conn->status_flags |= ARGOS_NET_STATS_CONN_UP;
    conn->connect_failed = 0;

    /* reset backoff upon successful connects */
    conn->cur_backoff = conn->init_backoff;

    /* set last-send time to current time */
    if (gettimeofday(&conn->last_send, NULL) != 0) {
        orion_log_crit_errno("gettimeofday");
        return;
    }

    /* change our write-priority (have to remove and then re-add fd) */
    int rv = async_remove_fd(conn->sock);
    if (rv != 0)
        orion_log_crit_errnof("async_remove_fd(%d)", conn->sock);

    rv = async_add_write_fd(conn->sock, ARGOS_NET_WRITE_ASYNCPRIO,
        writable_cb, write_cb, conn);
    if (rv != 0)
        orion_log_crit_errnof("async_add_write_fd(%d)", conn->sock);

    rv = async_add_read_fd(conn->sock, ARGOS_NET_READ_ASYNCPRIO,
        readable_cb, read_cb, conn);
    if (rv != 0)
        orion_log_crit_errnof("async_add_read_fd(%d)", conn->sock);

    /*
     * finally, write a handshake message to the socket (we assume that socket
     * is writable since we just connected
     */
    ssize_t len = socket_send(conn, &conn->handshake, sizeof(conn->handshake));
    if (len != -1) {
        /* make this callback AFTER everything else */
        if (conn->connecthandler != NULL)
            conn->connecthandler(conn, conn->connecthandler_user);
    }
}

static int
handle_connect_failure(struct argos_net_conn *conn)
{
    switch (errno) {
        /* these errors indicate some kind of programming error */
    case EBADF:
    case ENOTSOCK:
    case EAFNOSUPPORT:
    case EFAULT:
        /* fall through */

        /*
         * generally, these are non-fatal, but should never happen in this
         * code; if they do, this indicates a programming error
         */
    case EISCONN:
    case EALREADY:
        orion_log_crit_errno("connect");
        kill_connection(conn);
        orion_log_crit("unexpected connect() error; connection is now dead");
        return -1;
        
        /* these are transient errors; we retry connecting */
    case EADDRNOTAVAIL:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case ENETUNREACH:
    case EHOSTUNREACH:
    case EADDRINUSE:
    case ECONNRESET:

        /*
         * EAGAIN is NOT the same as EINPROGRESS; it means that the server's
         * connection backlog is full
         */
    case EAGAIN:
        if (!conn->connect_failed) {
            orion_log_warn_errno("connect");
            conn->connect_failed = 1;
        }
        reset_connection(conn, 0);
        return 0;

        /* these aren't really errors; the connect() should still work */
    case EINPROGRESS:
        /*
         * this errno is ok if returned by connect() itself, but shouldn't be
         * returned via error slippage from a recv() after a failed connect
         */
        if (conn->state == ARGOS_NET_CONN_CONNECTING) {
            orion_log_crit_errno("read after failed connect");
            kill_connection(conn);
            orion_log_crit("unexpected recv() error; connection is now dead");
        }
        /* fall through */

    case EINTR:
        orion_log_debug("connect() in progress (\"%s\")", strerror(errno));
        conn->state = ARGOS_NET_CONN_CONNECTING;
        return 0;

    default:
        /* unknown errno */
        orion_log_crit_errno("read after failed connect");
        orion_log_crit("unexpected connect errno");
        kill_connection(conn);
        return -1;
    }
}

static void
kill_connection(struct argos_net_conn *conn)
{
    if (conn->reconnect_evt_reg != NULL) {
        if (async_cancel(conn->reconnect_evt_reg) != 0)
            orion_log_crit_errno("async_cancel");
    }

    if (conn->sock != 0)
        close_socket(conn->sock);
    conn->state = ARGOS_NET_CONN_DEAD;
}

static void
process_inbuf(struct argos_net_conn *conn)
{
    while (buffer_len(conn->inbuf) >= sizeof(struct argos_net_minimal_msg)) {
        struct argos_net_minimal_msg *header =
            (struct argos_net_minimal_msg *)buffer_head(conn->inbuf);

        uint16_t msgtype = ntohs(header->msgtype);
        uint32_t msglen = ntohl(header->msglen);

        /* check that message type and length are valid */
        if (ARGOS_NET_VALIDATE_MSGTYPE(msgtype) == 0) {
            orion_log_crit("invalid message type received; type=%hu, len=%u",
                msgtype, msglen);
            reset_connection(conn, 1 /* flush buffers */);
            return;
        }

        if (ARGOS_NET_VALIDATE_MSGLEN(msgtype, msglen) == 0) {
            orion_log_crit("invalid message len received; type=%hu, len=%u",
                msgtype, msglen);
            reset_connection(conn, 1 /* flush buffers */);
            return;
        }

        if (msglen > buffer_len(conn->inbuf)) {
            /* complete message not yet received */
            if (msglen > buffer_size(conn->inbuf)) {
                /* error - message is bigger than the entire inbuf */
                orion_log_err("inbuf too small for msgtype %hu (len=%u)",
                    msgtype, msglen);
                reset_connection(conn, 1 /* flush buffers */);
                return;
            }

            /* wait for more bytes to arrive on socket */
            break;
        }

        /* ok great, message length must be valid - process it */
        switch (msgtype) {
        case ARGOS_NET_CLOSECONN_MSGTYPE: {
            struct argos_net_closeconn_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            orion_log_info("received close-connection message from server");
            reset_connection(conn, 1 /* flush buffers */);
            break;
        }

        case ARGOS_NET_ERROR_MSGTYPE: {
            struct argos_net_error_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            char buf[ARGOS_NET_MAX_ERR_LEN+1];
            ssize_t bodylen = msglen - sizeof(msg);
            rv = buffer_read(conn->inbuf, buf, bodylen);
            assert(rv >= 0);
            buf[bodylen] = '\0';

            if (conn->errhandler != NULL)
                conn->errhandler(ntohs(msg.errnum), buf, conn->errhandler_user);
            else
                orion_log_err("[server] %s (%s)", strerror(ntohs(msg.errnum)),
                    buf);
            break;
        }

        case ARGOS_NET_HANDSHAKE_MSGTYPE: {
            struct argos_net_handshake_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            /* sniffers should never receive handshake messages */
            orion_log_crit("received handshake message from server");
            reset_connection(conn, 1 /* flush buffers */);
            break;
        }

        case ARGOS_NET_PCAP_MSGTYPE: {
            struct argos_net_pcap_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            size_t bodylen = msglen - sizeof(msg);
            assert(bodylen == ntohl(msg.caplen));

            if (conn->pkthandler == NULL) {
                int rv = buffer_discard(conn->inbuf, bodylen);
                assert(rv >= 0);
                break;
            }

            struct pcap_pkthdr pcap_hdr;
            pcap_hdr.len = ntohl(msg.pktlen);
            pcap_hdr.caplen = ntohl(msg.caplen);
            pcap_hdr.ts.tv_sec = ntohl(msg.ts_sec);
            pcap_hdr.ts.tv_usec = ntohl(msg.ts_usec);

            /*
             * index directly into buffer if possible (i.e. if the data
             * doesn't wrap in the buffer)
             */
            if (buffer_len(conn->inbuf) >= bodylen) {
                conn->pkthandler(&pcap_hdr, buffer_head(conn->inbuf),
                    conn->pkthandler_user);
                buffer_discard(conn->inbuf, bodylen);
            } else {
                /* data wraps; need to copy into a temporary buffer */
                u_char tempbuf[ARGOS_NET_MAX_PKT_LEN];
                buffer_read(conn->inbuf, tempbuf, bodylen);
                conn->pkthandler(&pcap_hdr, tempbuf, conn->pkthandler_user);
            }
            break;
        }

        case ARGOS_NET_SETBPF_MSGTYPE: {
            struct argos_net_setbpf_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            char buf[ARGOS_NET_MAX_BPF_LEN+1];
            size_t bodylen = msglen - sizeof(msg);
            rv = buffer_read(conn->inbuf, buf, bodylen);
            assert(rv >= 0);
            buf[bodylen] = '\0';

            if (conn->bpfhandler != NULL)
                conn->bpfhandler(buf, conn->bpfhandler_user);
            /* else, just discard and ignore */
            break;
        }

        case ARGOS_NET_SETCHAN_MSGTYPE: {
            struct argos_net_setchan_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            if (conn->chanhandler != NULL)
                conn->chanhandler(ntohs(msg.chan), conn->chanhandler_user);
            /* else, just discard and ignore */
            break;
        }

        case ARGOS_NET_STARTCLICK_MSGTYPE: {
            struct argos_net_startclick_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            size_t bodylen = msglen - sizeof(msg);
            char *click_conf = malloc(bodylen+1);
            if (click_conf == NULL) {
                char errmsg[256];
                snprintf(errmsg, sizeof(errmsg), "malloc(%d): %s", bodylen,
                    strerror(errno));

                orion_log_crit_errno("malloc()");
                argos_net_send_errmsg(conn, errno, errmsg);
                kill_connection(conn);
                return;
            }

            rv = buffer_read(conn->inbuf, click_conf, bodylen);
            assert(rv >= 0);
            click_conf[bodylen] = '\0';

            /* is this click config any different from the last one we got? */
            uint32_t key = ntohl(msg.key);
            if (key == conn->click_config_key) {
                /* keys match; we can ignore this message */
                orion_log_debug("click-configuration keys match (%d)", key);
            } else {
                /* keys don't match; need to run this new configuration */
                orion_log_debug("new click-configuration key: %d", key);
                conn->click_config_key = key;
                if (conn->clickhandler != NULL)
                    conn->clickhandler(click_conf, conn->clickhandler_user);
            }

            free(click_conf);
            break;
        }

        case ARGOS_NET_STATS_MSGTYPE: {
            struct argos_net_stats_msg msg;
            int rv = buffer_read(conn->inbuf, &msg, sizeof(msg));
            assert(rv >= 0);

            orion_log_warn("received stats message from server");
            break;
        }

        default:
            orion_log_crit("process_inbuf() of net.c out of sync with net.h;"
                " no switch case for msgtype %hu", msgtype);
            kill_connection(conn);
        }
    }
}

static void
reconnect_event(void *arg)
{
    struct argos_net_conn *conn = arg;
    assert(conn->state == ARGOS_NET_CONN_BACKOFF);
    conn->state = ARGOS_NET_CONN_IDLE;
    conn->reconnect_evt_reg = NULL;

    (void) attempt_connect(conn);
}

static void
reset_connection(struct argos_net_conn *conn, int flush_buffers)
{
    if (flush_buffers) {
        buffer_empty(conn->inbuf);
        buffer_empty(conn->outbuf);
        buffer_empty(conn->pktbuf);
    } else {
        if (conn->outbuf_unsync) {
            /* 
             * Even if flush_buffers=0, we still need to flush the outbuf if its
             * unsynced (otherwise we might get out of sync when we resume
             * sending to the server after reconnecting).
             */
            buffer_empty(conn->outbuf);
        }

        /*
         * always flush inbuf for the same reason (could use a variable to avoid
         * unnecessary flushes...)
         */
        buffer_empty(conn->inbuf);
    }

    /* if connection is shutting down, check if outbuf is now empty */
    if (conn->shutdown && buffers_are_empty(conn)) {
        kill_connection(conn);
        return;
    }

    close_socket(conn->sock);

    conn->sock = 0;
    conn->status_flags |= ARGOS_NET_STATS_CONN_DOWN;

    /* schedule an reconnection event */
    conn->state = ARGOS_NET_CONN_BACKOFF;
    conn->reconnect_evt_reg =
        async_schedule_sec(conn->cur_backoff, reconnect_event, conn, 0);

    if (conn->reconnect_evt_reg == NULL) {
        orion_log_errno("async_schedule_sec");
        kill_connection(conn);
        orion_log_err("failed to schedule reconnection event"
            "; connection is now dead");
    }

    /* exponentially increase backoff */
    conn->cur_backoff *= 2;
    if (conn->cur_backoff > conn->max_backoff)
        conn->cur_backoff = conn->max_backoff;

    /* make this callback last */
    if (conn->breakhandler != NULL)
        conn->breakhandler(conn, conn->breakhandler_user);
}

static ssize_t
socket_send(struct argos_net_conn *conn, const void *msg, size_t len)
{
#if ARGOS_NET_TRACE_IO
    struct timeval start;
    if (gettimeofday(&start, NULL) != 0) {
        orion_log_crit_errno("gettimeofday");
        return -1;
    }
#endif /* #if ARGOS_NET_TRACE_IO */

    ssize_t sentlen = send(conn->sock, msg, len, 0);
    if (sentlen == -1) {
        if (IS_NETWORK_ERROR(errno)) {
            /* network error; reset our connection */
            orion_log_warn_errno("send() failed");
            reset_connection(conn, 0);
        } else {
            /* anything else is a fatal error */
            orion_log_crit_errno("send");
            kill_connection(conn);
            orion_log_crit("unexpected send() error; connection is now dead");
        }

        return -1;
    } else {
        /* send() succeeded */
        assert(sentlen > 0);

        /* this variable is used even if ARGOS_NET_TRACE_IO is false */
        struct timeval end;
        if (gettimeofday(&end, NULL) != 0) {
            orion_log_crit_errno("gettimeofday");
            return -1;
        }

#if ARGOS_NET_TRACE_IO
        struct timeval elapsed;
        orion_time_subtract(&end, &start, &elapsed);
        float elapsed_msec = elapsed.tv_sec*1000 + (float)elapsed.tv_usec/1000;

        orion_log_debug("sent %u bytes in %.2f ms (%.2f MB/s); requested %u",
            sentlen, elapsed_msec, ((sentlen/elapsed_msec)*1000)/(1024*1024), len);
#endif /* #if ARGOS_NET_TRACE_IO */

        conn->bytes_sent += sentlen;
        conn->last_send = end;
        conn->stall_logged = 0;
        return sentlen;
    }
}

/*
 * async callbacks (all static)
 */

static int
readable_cb(int fd, void *arg)
{
    struct argos_net_conn *conn = arg;

    /*
     * We are ready to read if we are connected and have room in the input
     * buffer.
     */
    return ((conn->state == ARGOS_NET_CONN_CONNECTED) &&
        (buffer_remaining(conn->inbuf) > 0));
}

static int
writable_cb(int fd, void *arg)
{
    struct argos_net_conn *conn = arg;

    /*
     * We are ready to write if, (a) we are connecting (because connect()
     * completion, whether successfully or not, is signalled by writability on
     * the socket), or (b) we are connected and have data in the buffer waiting
     * to be sent.
     */
    if (conn->state == ARGOS_NET_CONN_CONNECTING) return 1;

    if (conn->state == ARGOS_NET_CONN_CONNECTED) {
        if (buffer_len(conn->outbuf) > 0)
            return 1;

        /*
         * outbuf is empty, so we report the socket as non-writable; we also set
         * the last-send time to now to prevent erroneous 'network stalled'
         * messages from appearing when next we do have something to send (in
         * effect, we are keeping the "timer" from ticking while the buffer is
         * empty)
         */
        if (gettimeofday(&conn->last_send, NULL) != 0)
            orion_log_crit_errno("gettimeofday");

         return 0;
    }
    else /* conn->state not CONNECTING and not CONNECTED */
        return 0;
}

static void
read_cb(int fd, void *arg)
{
    struct argos_net_conn *conn = arg;

    /*
     * We only want to do reads if conn->state == NET_CONN_CONNECTED, but we
     * don't assert() this because its possible for this socket to be selected
     * simultaneously for both a read and a write and then for our state to
     * change during the write attempt.
     */
    if (conn->state != ARGOS_NET_CONN_CONNECTED)
        return;

    ssize_t len = recv(conn->sock, buffer_tail(conn->inbuf), buffer_remaining(conn->inbuf), 0);
    if (len == -1) {
        if (IS_NETWORK_ERROR(errno)) {
            /* network error; reset our connection */
            orion_log_warn_errno("recv");
            reset_connection(conn, 0);
        } else if (errno == EINTR) {
            /* don't care; ignore it */
        } else {
            /* anything else is a fatal error */
            orion_log_crit_errno("recv");
            kill_connection(conn);
            orion_log_crit("unexpected recv() error; connection is now dead");
        }
    } else if (len == 0) {
        /* EOF received (maybe other end is shutting down?) */
        orion_log_info("EOF received from remote end - closing socket");
        if (buffer_len(conn->inbuf) > 0)
            orion_log_warn("incomplete message received (inbuflen=%d)",
                buffer_len(conn->inbuf));
        reset_connection(conn, 1 /* flush buffers */);
    } else {
        /* ok, we read some data into the inbuf; update the buffer */
        int rv = buffer_expand(conn->inbuf, len);
        if (rv == -1) KABOOM("buffer_expand");

        conn->bytes_recv += len;

        /* now process (i.e. look for complete messages in) the inbuf */
        process_inbuf(conn);
    }
}

static void
write_cb(int fd, void *arg)
{
    struct argos_net_conn *conn = arg;

    if (conn->state == ARGOS_NET_CONN_CONNECTING) {
        handle_connect(conn);
    }
    else if (conn->state == ARGOS_NET_CONN_CONNECTED) {
        /* this callback shouldn't happen unless outbuf is non-empty */
        size_t datalen = buffer_len(conn->outbuf);
        assert(datalen > 0);

        /*
         * when possible, we want to make sure to feed send() large blocks of
         * data at a time, so if there is only a little data in the outbuf, try
         * to get some more by compressing and moving over some of the pktbuf
         */
        if (datalen < SEND_SOFT_MIN) {
            (void) compress_and_xfer(conn, 0 /* don't force */);
            datalen = buffer_len(conn->outbuf);
        }

        ssize_t len = socket_send(conn, buffer_head(conn->outbuf), datalen);
        if (len != -1) {
            if (buffer_discard(conn->outbuf, len) == -1)
                KABOOM("buffer_discard");

            /*
             * When a partial-send occurs, this means we might have sent part of
             * a message and left the remainder sitting at the head of the
             * outbuf.  This is not a problem for the server (it will receive
             * and buffer the portion that was sent, waiting for us to send the
             * remainder) - however, it means that we cannot arbitrarily send
             * things down the socket until we finish off this partially-sent
             * message.  We call this state "unsynced" because we don't know if
             * we stopped sending on a message boundary or not.
             */
            if (buffer_len(conn->outbuf) == 0)
                conn->outbuf_unsync = 0;
            else if (datalen != len)
                conn->outbuf_unsync = 1;

            /* if connection is shutting down, check if buffers are now empty */
            if (conn->shutdown && buffers_are_empty(conn))
                kill_connection(conn);
        }
    }
}
