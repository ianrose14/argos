/*
 * Author: Ian Rose
 * Date Created: Feb 17, 2009
 */

#ifndef _ARGOS_MODULES_TCPFLOWS_H_
#define _ARGOS_MODULES_TCPFLOWS_H_

/* system includes */
#include <unistd.h>
#include <netinet/in.h>

/* local includes */
#include <pktparse.h>
#include "argos.h"
#include "rangemap.h"
#include "uthash.h"
#include "argos/config.h"


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct argos_tcp_endpoint {
    struct in_addr addr;
    u_short port;
} __attribute__((__packed__));

struct argos_tcp_flow_id {
    struct argos_tcp_endpoint src, dst;
} __attribute__((__packed__));

/*
 * a "flow" is defined unidirectionally; hence, a TCP connection always consists
 * of two distinct flows (one in each direction) although one or both of the
 * flows might be empty (no data transferred).
 */
struct argos_tcp_flow {
    UT_hash_handle hh;      /* uthash handle (required for hashing) */
    struct argos_tcp_flow_id id;  /* hash key */
    char desc[48];          /* for convenience, format is "ip:port -> ip:port" */
    time_t first_updated, last_updated;

    /* link level addresses */
    u_char transmitter[6], bssid[6];

    /* count of all captured packets (incl. duplicates) */
    uint32_t captured_count;

    /* special (tcp flagged) packets */
    u_char syn_captured, fin_captured, rst_captured;  /* booleans */
    uint32_t syn_seq, fin_seq, rst_seq;

    /* sum and minimum of all SNR values from captured packets */
    int32_t snr_sum;
    int16_t snr_min, snr_max;

    /* whether some data was intentionally dropped (not saved) */
    u_char data_truncated;

    /* rangemap of all seqnums that were captured (but not necessarily stored) */
    rangemap_t *captured_data_seqs;

    /* rangemap of the seqnums of packets that were actually stored */
    rangemap_t *stored_data_seqs;

    /*
     * buffer to store tcp payloads.  array index and tcp seqnum are related by:
     *   [array index] + stored_data_headseq = [tcp seqnum]
     */
    u_char *stored_data;
    uint32_t stored_data_size;     /* allocated length */
    uint32_t stored_data_headseq;
};

/* required signature for tcpflow handler functions */
typedef void (*tcpflow_hdlr)(const struct argos_tcp_flow *);


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_tcpflows_exec_task(const struct timeval *clock);

int argos_tcpflows_init(const struct argos_config_file *conf);

int argos_tcpflows_finalize(void);

void argos_tcpflows_handle_packet(const struct argos_producer *producer,
    const struct packet *pkt, uint8_t channel);

int argos_tcpflows_register_handler(const char * restrict name,
    tcpflow_hdlr func);

#endif  /* #ifndef _ARGOS_MODULES_TCPFLOWS_H_ */
