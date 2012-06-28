/*
 * Author: Ian Rose
 * Date Created: Nov 18, 2009
 */

#ifndef _ARGOS_NET_H_
#define _ARGOS_NET_H_

/* system includes */
#include <pcap/pcap.h>
#include <netinet/in.h>

/* local includes */
#include "async.h"
#include "argos/net_proto.h"


/***************/
/*  CONSTANTS  */
/***************/

/* defaults for command line arguments / config file settings */
#define ARGOS_DEF_NET_INBUF_KB      100        /* 100 KB */
#define ARGOS_DEF_NET_OUTBUF_KB     (5*1024)   /* 5 MB */
#define ARGOS_DEF_NET_PKTBUF_KB     (5*1024)   /* 5 MB */

/* priority levels to use when registering file descriptors with async */
#define ARGOS_NET_CONNECT_ASYNCPRIO  1
#define ARGOS_NET_READ_ASYNCPRIO     2
#define ARGOS_NET_WRITE_ASYNCPRIO    3

/* how long to wait before attempting to reconnect after a network failure */
#define ARGOS_NET_DEF_INIT_BACKOFF 5
#define ARGOS_NET_DEF_MAX_BACKOFF 5  /* was 60 */

/* how long we are to wait for network-writability before logging a warning */
#define ARGOS_NET_STALL_TIMEOUT 10  /* seconds */

/* what compression algorithm (if any) should be used by the network component */
#define ARGOS_NET_USE_COMPRESSION ARGOS_NET_COMPRESS_QUICKLZ


#ifndef ARGOS_NET_USE_COMPRESSION
#define ARGOS_NET_USE_COMPRESSION ARGOS_NET_COMPRESS_NONE
#endif

/* delayed includes */
#if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_LZO
#include "lzo/lzo1x.h"
#elif ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_QUICKLZ
#include "quicklz.h"
#endif


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct argos_net_conn;  /* need a forward declaration of this type */

typedef void (*argos_net_basichandler)(struct argos_net_conn*, void*);

typedef void (*argos_net_chanhandler)(uint16_t, void*);

typedef void (*argos_net_strhandler)(const char*, void*);

typedef void (*argos_net_errhandler)(uint16_t, const char*, void*);

typedef void (*argos_net_pkthandler)(const struct pcap_pkthdr*,
    const u_char*, void*);

enum argos_net_state {
    ARGOS_NET_CONN_IDLE=0,
    ARGOS_NET_CONN_BACKOFF,
    ARGOS_NET_CONN_CONNECTING,
    ARGOS_NET_CONN_CONNECTED,
    ARGOS_NET_CONN_DEAD
};

struct argos_net_conn {
    int sock;
    int shutdown;  /* boolean - is this connection shutdown? */
    int dlt;
    enum argos_net_state state;
    u_char connect_failed;
    uint16_t status_flags;  /* see enum values in argos/net.h */
    struct sockaddr_in remote_addr;
    time_t cur_backoff;  /* time to wait after a network error */
    time_t init_backoff;
    time_t max_backoff;
    async_evt_reg *reconnect_evt_reg;  /* handle for reconnection event */
    async_evt_reg *compress_evt_reg;   /* handle for compression event */

    struct timeval last_send;  /* used to detect network stalls */
    u_char stall_logged;  /* prevents spamming the log */
    uint32_t bytes_sent;  /* for stats reporting only */
    uint32_t bytes_recv;  /* for stats reporting only */

    /* key of the last click configuration received */
    uint32_t click_config_key;

    /* buffers */
    struct argos_net_handshake_msg handshake;
    struct buffer *inbuf;
    struct buffer *pktbuf;
    struct buffer *outbuf;
    u_char outbuf_unsync;  /* whether outbuf is (potentially) unsynced */
#if ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_LZO
    lzo_byte lzo_wrk_space[LZO1X_1_MEM_COMPRESS];
#elif ARGOS_NET_USE_COMPRESSION == ARGOS_NET_COMPRESS_QUICKLZ
    char qlz_scratch[QLZ_SCRATCH_COMPRESS];
#endif

    /* callbacks */
    argos_net_strhandler bpfhandler;
    void *bpfhandler_user;
    argos_net_basichandler breakhandler;
    void *breakhandler_user;
    argos_net_chanhandler chanhandler;
    void *chanhandler_user;
    argos_net_strhandler clickhandler;
    void *clickhandler_user;
    argos_net_basichandler connecthandler;
    void *connecthandler_user;
    argos_net_errhandler errhandler;
    void *errhandler_user;
    argos_net_pkthandler pkthandler;
    void *pkthandler_user;
};

struct argos_net_stats {
    struct timeval ts;
    uint32_t duration_ms;
    uint32_t kern_recv;
    uint32_t kern_drop;
    uint32_t app_recv;
    struct timeval usr_time;
    struct timeval sys_time;
    uint32_t maxrss_kbytes;  /* measured in kilobytes, like getrusage */
    struct timeval pcap_opened;
};


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

void argos_net_close(struct argos_net_conn *conn);

struct argos_net_conn *argos_net_client_create(struct sockaddr_in *remote_addr,
    int dlt, const struct sockaddr_in *client_ip, size_t inbufsz, size_t outbufsz,
    size_t pktbufsz);

int argos_net_init(void);

size_t argos_net_queue_room(const struct argos_net_conn *conn);

void argos_net_shutdown(struct argos_net_conn *conn);

ssize_t argos_net_send_errmsg(struct argos_net_conn *conn, uint16_t errnum,
    const char *errmsg);

ssize_t argos_net_send_packet(struct argos_net_conn *conn,
    const struct pcap_pkthdr *h, const u_char *sp, uint8_t channel);

ssize_t argos_net_send_stats(struct argos_net_conn *conn,
    const struct argos_net_stats *stats);

void argos_net_set_connect_backoffs(struct argos_net_conn *conn,
    time_t initial_backoff, time_t max_backoff);

argos_net_strhandler argos_net_set_bpfhandler(struct argos_net_conn *conn,
    argos_net_strhandler handler, void *user);

argos_net_basichandler argos_net_set_breakhandler(struct argos_net_conn *conn,
    argos_net_basichandler handler, void *user);

argos_net_chanhandler argos_net_set_chanhandler(struct argos_net_conn *conn,
    argos_net_chanhandler handler, void *user);

argos_net_strhandler argos_net_set_clickhandler(struct argos_net_conn *conn,
    argos_net_strhandler handler, void *user);

argos_net_basichandler argos_net_set_connecthandler(struct argos_net_conn *conn,
    argos_net_basichandler handler, void *user);

argos_net_errhandler argos_net_set_errhandler(struct argos_net_conn *conn,
    argos_net_errhandler handler, void *user);

argos_net_pkthandler argos_net_set_pkthandler(struct argos_net_conn *conn,
    argos_net_pkthandler handler, void *user);


#endif  /* #ifndef _ARGOS_NET_H_ */
