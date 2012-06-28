/*
 * Author: Ian Rose
 * Date Created: Mar 25, 2009
 *
 * Common declarations related to the Argos network protocol.
 */

#ifndef _ARGOS_NET_PROTO_H_
#define _ARGOS_NET_PROTO_H_

#ifdef __cplusplus
extern "C" {
#endif


/***************/
/*  CONSTANTS  */
/***************/

#define ARGOS_NET_MAGICNUM 0xd34df001

enum argos_net_pkt_types {
    ARGOS_NET_NULL_MSGTYPE=0,
    ARGOS_NET_HANDSHAKE_MSGTYPE=1,
    ARGOS_NET_PCAP_MSGTYPE=2,
    ARGOS_NET_STATS_MSGTYPE=3,
    ARGOS_NET_ERROR_MSGTYPE=4,
    ARGOS_NET_COMPRESS_MSGTYPE=5,
    /* ARGOS_NET_PING_MSGTYPE=6,  (deprecated) */
    ARGOS_NET_SETBPF_MSGTYPE=32,
    ARGOS_NET_SETCHAN_MSGTYPE=33,
    ARGOS_NET_CLOSECONN_MSGTYPE=34,
    ARGOS_NET_STARTCLICK_MSGTYPE=35,
    ARGOS_NET_CLICKPKT_MSGTYPE=36
};

/* cannot be an enum b/c we need to access them in the preprocessor */
#define ARGOS_NET_COMPRESS_NONE     0
#define ARGOS_NET_COMPRESS_LZO      1
#define ARGOS_NET_COMPRESS_QUICKLZ  2

/*
 * According to the QuickLZ manual, the maximum that a data buffer can expand
 * during compression is 400 bytes.  Also, compression should always result in
 * at least 9 bytes (since qlz_size_decompressed takes "the first 9 bytes of
 * compressed data as argument").
 * http://www.quicklz.com/manual.html
 */
#define QLZ_MAX_INFLATE 400
#define QLZ_MIN_COMPRESS_SIZE 9

#define ARGOS_NET_DEF_SERVER_HOSTNAME "citysense.net"
#define ARGOS_NET_DEF_SERVER_PORT 9605

/*
 * in set-chan messages, if chan is in the low range, then its a channel number,
 * whereas if its in the high range, then its the id of a channel-hopping
 * pattern.
 */
#define ARGOS_NET_MAX_CHAN 255

/*
 * maximum "payload" sizes for messages that are not fixed-sized */
#define ARGOS_NET_MAX_PKT_LEN 2048
#define ARGOS_NET_MAX_BPF_LEN 2047
#define ARGOS_NET_MAX_ERR_LEN 1023
#define ARGOS_NET_MAX_COMPRESS_LEN (1024*1024)

#define ARGOS_NET_CLICKPKT_ANNO_SIZE 48

/* reserved value for values that are not set in the packet */
#define ARGOS_NET_CLICKPKT_UNDEF 0x7FFFFFFF


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

/*
 * All messages start with the following fields:
 * - a 2-byte message-type
 * - 2 unused bytes (can be used by underlying packet type)
 * - a 4-byte message-length
 */
struct argos_net_minimal_msg {
    uint16_t msgtype;
    uint8_t unused_space[2];
    uint32_t msglen;
} __attribute__((__packed__));

struct argos_net_handshake_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_HANDSHAKE_MSGTYPE */
    uint8_t unused_space[2];
    uint32_t msglen;
    uint32_t magicnum;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t dlt;
    uint32_t ip;
} __attribute__((__packed__));

struct argos_net_pcap_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_PCAP_MSGTYPE */
    uint8_t channel;   /* using 1 byte of unused_space */
    uint8_t unused_space[1];
    uint32_t msglen;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t pktlen;  /* technically redundant msglen, but convenient */
    uint32_t caplen;  /* technically redundant with msglen, but convenient */
    /* next follows the first caplen bytes of the captured packet */
} __attribute__((__packed__));

struct argos_net_stats_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_STATS_MSGTYPE */
    uint16_t flags;    /* using unused_space */
    uint32_t msglen;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t duration_ms;
    uint32_t kern_recv;
    uint32_t kern_drop;
    uint32_t app_recv;
    uint32_t usr_time_ms;
    uint32_t sys_time_ms;
    uint32_t maxrss_kbytes;
    uint32_t net_sent_bytes;
    uint32_t pcap_opened_sec;
    uint32_t pcap_opened_usec;
} __attribute__((__packed__));

/* stats message flag values */
enum {
    ARGOS_NET_STATS_CONN_UP=1,
    ARGOS_NET_STATS_CONN_DOWN=2,
    ARGOS_NET_STATS_CONN_STALLED=4
};

struct argos_net_error_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_ERROR_MSGTYPE */
    uint16_t errnum;   /* using unused_space */
    uint32_t msglen;
    /* next follows a string error message */
} __attribute__((__packed__));

struct argos_net_compress_msg {
    uint16_t msgtype;    /* must equal ARGOS_NET_COMPRESS_MSGTYPE */
    uint8_t algorithm;   /* must be one of ARGOS_NET_COMPRESS_xxx */
    uint8_t crc32_used;  /* whether the crc32 field was actually filled or not */
    uint32_t msglen;
    uint32_t orig_len;   /* length of block before compression */
    uint32_t crc32;
    /* next follows an block of compressed argos_net_pcap_msg messages */
} __attribute__((__packed__));

struct argos_net_setbpf_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_SETBPF_MSGTYPE */
    uint8_t unused_space[2];
    uint32_t msglen;
    /* next follows a pcap filter expression in string format */
} __attribute__((__packed__));

/*
 * as a special case, the bpf expression "0" (which is not a legal filter) means
 * "close this pcap descriptor entirely"
 */
#define ARGOS_NET_CLOSEFD_BPF "0"

struct argos_net_setchan_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_SETCHAN_MSGTYPE */
    uint16_t chan;     /* using unused_space */
    uint32_t msglen;
} __attribute__((__packed__));

struct argos_net_closeconn_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_CLOSECONN_MSGTYPE */
    uint8_t unused_space[2];
    uint32_t msglen;
} __attribute__((__packed__));

struct argos_net_startclick_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_STARTCLICK_MSGTYPE */
    uint8_t unused_space[2];
    uint32_t msglen;
    uint32_t key;      /* uniquely identifies the click configuration */
    /* next follows a click router configuration */
} __attribute__((__packed__));

struct argos_net_clickpkt_msg {
    uint16_t msgtype;     /* must equal ARGOS_NET_CLICKPKT_MSGTYPE */
    uint8_t packet_type;  /* using 1 byte of unused_space */
    uint8_t unused_space[1];
    uint32_t msglen;
    int32_t mac_offset;   /* offset from data() of the mac header */
    int32_t net_offset;   /* offset from data() of the network header */
    int32_t trans_offset; /* offset from data() of the transport header */
    uint32_t ts_sec;
    uint32_t ts_usec;
    char anno[ARGOS_NET_CLICKPKT_ANNO_SIZE];
    /*
     * next follows the packet's data buffer, of length
     * (msglen - sizeof(struct argos_net_clickpkt_msg))
     */
} __attribute__((__packed__));


/************/
/*  MACROS  */
/************/

/* returns whether or not the specified message-type is valid */
#define ARGOS_NET_VALIDATE_MSGTYPE(type)                                \
    ((type == ARGOS_NET_HANDSHAKE_MSGTYPE) ||                           \
        (type == ARGOS_NET_PCAP_MSGTYPE) ||                             \
        (type == ARGOS_NET_STATS_MSGTYPE) ||                            \
        (type == ARGOS_NET_ERROR_MSGTYPE) ||                            \
        (type == ARGOS_NET_COMPRESS_MSGTYPE) ||                         \
        (type == ARGOS_NET_SETBPF_MSGTYPE) ||                           \
        (type == ARGOS_NET_SETCHAN_MSGTYPE) ||                          \
        (type == ARGOS_NET_CLOSECONN_MSGTYPE) ||                        \
        (type == ARGOS_NET_STARTCLICK_MSGTYPE) ||                       \
        (type == ARGOS_NET_CLICKPKT_MSGTYPE))

/* returns whether or not the specified length is valid for the message-type */
#define ARGOS_NET_VALIDATE_MSGLEN(type, len)                            \
    (((type == ARGOS_NET_HANDSHAKE_MSGTYPE) &&                          \
        (len == sizeof(struct argos_net_handshake_msg))) ||             \
        ((type == ARGOS_NET_PCAP_MSGTYPE) &&                            \
            (len >= sizeof(struct argos_net_pcap_msg)) &&               \
            (len <= sizeof(struct argos_net_pcap_msg) + ARGOS_NET_MAX_PKT_LEN)) || \
        ((type == ARGOS_NET_STATS_MSGTYPE) &&                           \
            (len == sizeof(struct argos_net_stats_msg))) ||             \
        ((type == ARGOS_NET_ERROR_MSGTYPE) &&                           \
            (len >= sizeof(struct argos_net_error_msg)) &&              \
            (len <= sizeof(struct argos_net_error_msg) + ARGOS_NET_MAX_ERR_LEN)) || \
        ((type == ARGOS_NET_COMPRESS_MSGTYPE) &&                        \
            (len >= sizeof(struct argos_net_compress_msg)) &&               \
            (len <= sizeof(struct argos_net_compress_msg) + ARGOS_NET_MAX_COMPRESS_LEN)) || \
        ((type == ARGOS_NET_SETBPF_MSGTYPE) &&                          \
            (len >= sizeof(struct argos_net_setbpf_msg)) &&             \
            (len <= sizeof(struct argos_net_setbpf_msg) + ARGOS_NET_MAX_BPF_LEN)) || \
        ((type == ARGOS_NET_SETCHAN_MSGTYPE) &&                         \
            (len == sizeof(struct argos_net_setchan_msg))) ||           \
        ((type == ARGOS_NET_CLOSECONN_MSGTYPE) &&                       \
            (len == sizeof(struct argos_net_closeconn_msg))) ||         \
        (type == ARGOS_NET_STARTCLICK_MSGTYPE) ||                       \
        (type == ARGOS_NET_CLICKPKT_MSGTYPE))

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ARGOS_NET_PROTO_H_ */
