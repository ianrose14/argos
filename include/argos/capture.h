/*
 * Author: Ian Rose
 * Date Created: Nov 18, 2009
 */

#ifndef _ARGOS_CAPTURE_H_
#define _ARGOS_CAPTURE_H_

/* system includes */
#include <pcap/pcap.h>
#include <netinet/in.h>

/* local includes */
#include "async.h"
#include "argos/common.h"
#include "argos/net.h"
#include "orion/config.h"


/***************/
/*  CONSTANTS  */
/***************/

/* priority levels to use when registering file descriptors with async */
#define ARGOS_CAP_PCAP_ASYNCPRIO    3

/*
 * delay a bit before starting to read from the file to give the server time to
 * send us any set-bpf commands that it wants to (it should send them
 * immediately after receiving a handshake command from us)
 */
#define ARGOS_CAP_OFFLINE_DELAY     5   /* seconds */

/* whether to set BIOCIMMEDIATE on pcap descriptors */
#define ARGOS_CAP_SET_BIOCIMMEDIATE 1

/* whether to set monitor mode on the capture interface */
#define ARGOS_CAP_SET_RFMON 0

/* size of BPF buffer to request */
#define ARGOS_CAP_BPF_BUFSIZE (512*1024)  /* 512 KB */


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct argos_capture_hdl {
    char if_name[ARGOS_MAX_IFNAME_LEN+1];
    int dlt, snaplen;
    u_short is_offline;   /* boolean */

    pcap_t *pcap_h;
    int pcap_fd;
    struct pcap_stat last_pcap_stat;

    /* function pointers and 'user' parameters */
    pcap_handler pkt_func;
    u_char *user;
    async_io_check readable;

    /* used to count packets/bytes returned by pcap_dispatch() */
    uint32_t capt_pkts;
    uint32_t capt_bytes;

    /* the file name (used only in offline mode) */
    char pcapfile[ARGOS_MAX_PATH_LEN+1];

    /* whether to pause between (offline) packets to mimic file capture timing */
    u_char use_file_timing;
};


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

/* methods implemented in sniffer/capture.c */

void argos_capture_close(struct argos_capture_hdl *handle);

int argos_capture_get_stats(struct argos_capture_hdl *handle,
    struct pcap_stat *stats);

struct argos_capture_hdl *argos_capture_create_live(const char *if_name,
    int dlt, int snaplen, pcap_handler pkt_func, u_char *user,
    async_io_check readable);

struct argos_capture_hdl *argos_capture_create_offline(const char *filename,
    u_char file_timing, pcap_handler pkt_func, u_char *user,
    async_io_check readable);

int argos_capture_set_filter(struct argos_capture_hdl *handle, const char *bpf_expr);

void argos_capture_start(struct argos_capture_hdl *handle, const char *bpf_expr);

#endif  /* #ifndef _ARGOS_CAPTURE_H_ */
