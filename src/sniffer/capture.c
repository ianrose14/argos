/*
 * Author: Ian Rose
 * Date Created: Jul 7, 2009
 *
 * Handles the packet-capture duties of the argos sniffer.
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <pcap/pcap.h>

/* local includes */
#include "async.h"
#include "argos/capture.h"
#include "argos/sniffer.h"
#include "orion/log.h"
#include "orion/time.h"


/***************/
/*  CONSTANTS  */
/***************/

/*
 * minimum dispatch size (in terms of number of packets returned) in order for
 * a message to be logged (can result in very verbose logging if this is set to
 * a small value)
*/
#define DISPATCH_LOG_MIN 100


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

/* callback for libpcap */
static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

static int start_capture(struct argos_capture_hdl *handle);

/* callback for async_loop() */
static void pcap_read_cb(int fd, void *user);


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

void
argos_capture_close(struct argos_capture_hdl *handle)
{
    if (handle->pcap_h == NULL) return;  /* already closed */

    if (async_remove_fd(handle->pcap_fd) != 0)
        orion_log_crit_errnof("async_remove_fd(%d)", handle->pcap_fd);
    pcap_close(handle->pcap_h);
    handle->pcap_h = NULL;
    orion_log_debug("closed %s pcap", (handle->is_offline ? "offline" : "live"));
}

int
argos_capture_get_stats(struct argos_capture_hdl *handle, struct pcap_stat *stats)
{
    /* if pcap descriptor is not open, just return all 0s */
    if (handle->pcap_h == NULL) {
        bzero(stats, sizeof(struct pcap_stat));
        return 0;
    }

    if (handle->is_offline) {
        /* offline capture does not provide stats (pcap_stats will fail) */
        bzero(stats, sizeof(struct pcap_stat));
        return 0;
    }

    struct pcap_stat pcap_stat;
    if (pcap_stats(handle->pcap_h, &pcap_stat) != 0) {
        orion_log_err("pcap_stats: %s", pcap_geterr(handle->pcap_h));
        return -1;
    }

    stats->ps_recv = pcap_stat.ps_recv - handle->last_pcap_stat.ps_recv;
    stats->ps_drop = pcap_stat.ps_drop - handle->last_pcap_stat.ps_drop;
    handle->last_pcap_stat = pcap_stat;
    return 0;
}

struct argos_capture_hdl *
argos_capture_create_live(const char *if_name, int dlt, int snaplen,
    pcap_handler pkt_func, u_char *user, async_io_check readable)
{
    struct argos_capture_hdl *handle = malloc(sizeof(struct argos_capture_hdl));
    if (handle == NULL)
        return NULL;

    bzero(handle, sizeof(struct argos_capture_hdl));

    size_t len = sizeof(handle->if_name);
    if (strlcpy(handle->if_name, if_name, len) >= len) {
        errno = ENAMETOOLONG;
        goto fail;
    }

    handle->snaplen = snaplen;
    handle->dlt = dlt;
    handle->is_offline = 0;
    handle->pkt_func = pkt_func;
    handle->user = user;
    handle->readable = readable;
    return handle;

 fail:
    free(handle);
    return NULL;
}

struct argos_capture_hdl *
argos_capture_create_offline(const char *filename, u_char file_timing,
    pcap_handler pkt_func, u_char *user, async_io_check readable)
{
    struct argos_capture_hdl *handle = malloc(sizeof(struct argos_capture_hdl));
    if (handle == NULL)
        return NULL;

    size_t len = sizeof(handle->pcapfile);
    if (strlcpy(handle->pcapfile, filename, len) >= len) {
        errno = ENAMETOOLONG;
        goto fail;
    }

    /* open pcap file just to check its datalink (and ensure its openable) */
    char ebuf[PCAP_ERRBUF_SIZE];
    ebuf[0] = '\0';
    pcap_t *pcap_h = pcap_open_offline(handle->pcapfile, ebuf);
    if (pcap_h == NULL) {
        orion_log_err("pcap_open_offline: %s", ebuf);
        errno = EIO;
        goto fail;
    }

    if (*ebuf) orion_log_warn("pcap_open_offline: %s", ebuf);
    handle->dlt = pcap_datalink(pcap_h);
    pcap_close(pcap_h);

    handle->use_file_timing = file_timing;
    handle->is_offline = 1;
    handle->pkt_func = pkt_func;
    handle->user = user;
    handle->readable = readable;
    return handle;

 fail:
    free(handle);
    return NULL;
}

int
argos_capture_set_filter(struct argos_capture_hdl *handle, const char *bpf_expr)
{
    char ebuf[PCAP_ERRBUF_SIZE];
    ebuf[0] = '\0';

    if (handle->pcap_h == NULL) {
        if (start_capture(handle) == -1)
            return -1;
    }

    /*
     * The pcap manpage stats that the netmask argument is only used to detect
     * IPv4 broadcast packets, and that a value of 0 can be supplied if you
     * don't care about that.  Since it doesn't make sense for use queries to
     * have anything to do with our local IP addresses, we don't even both look
     * up the netmask and just use 0 every time.
     */
    int netmask = 0;
    int optimize = 1;
    struct bpf_program bpf;
    if (pcap_compile(handle->pcap_h, &bpf, bpf_expr, optimize, netmask) == -1) {
        orion_log_err("pcap_compile: %s", pcap_geterr(handle->pcap_h));
        errno = EINVAL;
        return -1;
    }
    
    int rv = pcap_setfilter(handle->pcap_h, &bpf);
    pcap_freecode(&bpf);  /* always free, regardless of success/failure */

    if (rv == -1) {
        orion_log_err("pcap_setfilter: %s", pcap_geterr(handle->pcap_h));
        errno = EIO;
        return -1;
    }

    /* important: calling pcap_setfilter resets the kernel's stats! */
    bzero(&handle->last_pcap_stat, sizeof(struct pcap_stat));
    orion_log_debug("set pcap filter to \"%s\"", bpf_expr);
    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

static void
handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    struct argos_capture_hdl *handle = (struct argos_capture_hdl*)user;

    handle->capt_pkts++;
    handle->capt_bytes += h->caplen;
    handle->pkt_func(handle->user, h, sp);

    /* if the network queue is full, interrupt pcap_dispatch to stop packets */
    int rv = handle->readable(handle->pcap_fd, NULL);
    if (rv == 0) {
        orion_log_info("calling pcap_breakloop (pcap not readable)");
        pcap_breakloop(handle->pcap_h);
    }
}

static int
start_capture(struct argos_capture_hdl *handle)
{
    int rv;
    char ebuf[PCAP_ERRBUF_SIZE];
    ebuf[0] = '\0';

    /* reset stats to 0 */
    bzero(&handle->last_pcap_stat, sizeof(handle->last_pcap_stat));

    /* open pcap descriptor */
    if (handle->is_offline) {
        /* offline capture */
        handle->pcap_h = pcap_open_offline(handle->pcapfile, ebuf);
        if (handle->pcap_h == NULL) {
            orion_log_err("pcap_open_offline: %s", ebuf);
            return -1;
        }
    } else {
        handle->pcap_h = pcap_create(handle->if_name, ebuf);

        if (handle->pcap_h == NULL) {
            orion_log_err("pcap_create: %s", ebuf);
            return -1;
        }

        if (pcap_set_snaplen(handle->pcap_h, handle->snaplen) != 0) {
            orion_log_err("pcap_set_snaplen: %s", pcap_geterr(handle->pcap_h));
            return -1;
        }

        if (pcap_set_promisc(handle->pcap_h, 1) != 0) {
            orion_log_err("pcap_set_promisc: %s", pcap_geterr(handle->pcap_h));
            return -1;
        }

#if ARGOS_CAP_SET_RFMON
        char *cmd;
        if (asprintf(&cmd, "ifconfig %s -mediaopt adhoc", handle->if_name) == -1) {
            orion_log_errno("asprintf");
            return -1;
        }

        int exitcode = system(cmd);
        free(cmd);

        if (exitcode == -1) {
            orion_log_err("system() failed (-1)");
            return -1;
        } else if (exitcode == 127) {
            orion_log_err("system() failed to execute sh");
            return -1;
        } else if (exitcode != 0) {
            orion_log_err("ifconfig failed (%d)", exitcode);
        }

        if (pcap_can_set_rfmon(handle->pcap_h) == 0) {
            orion_log_err("pcap_can_set_rfmon returned 0 for device %s", handle->if_name);
            return -1;
        }

        if (pcap_set_rfmon(handle->pcap_h, 1) != 0) {
            orion_log_err("pcap_set_rfmon: %s", pcap_geterr(handle->pcap_h));
            return -1;
        }
#endif  /* #if ARGOS_CAP_SET_RFMON */

        if (pcap_set_buffer_size(handle->pcap_h, ARGOS_CAP_BPF_BUFSIZE) != 0) {
            orion_log_err("pcap_set_buffer_size: %s", pcap_geterr(handle->pcap_h));
            return -1;
        }

        if (pcap_activate(handle->pcap_h) != 0) {
            orion_log_err("pcap_activate: %s", pcap_geterr(handle->pcap_h));
            return -1;
        }

        /*
         * the following calls must be done AFTER pcap_activate():
         * pcap_setfilter
         * pcap_setdirection
         * pcap_set_datalink
         * pcap_getnonblock
         * pcap_setnonblock
         * pcap_stats
         * all reads/writes
         */

        if (pcap_set_datalink(handle->pcap_h, handle->dlt) == -1) {
            orion_log_err("pcap_set_datalink: %s", pcap_geterr(handle->pcap_h));
            pcap_close(handle->pcap_h);   /* treat this as a fatal error */
            return -1;
        }

        /* 
         * not sure that this is necessary, since we use select(), but click's
         * (userlevel) FromDevice element does it, so might as well to be safe.
         */
        if (pcap_setnonblock(handle->pcap_h, 1, ebuf) != 0) {
            orion_log_err("pcap_setnonblock: %s", ebuf);
            return -1;
        }

        int fd = pcap_get_selectable_fd(handle->pcap_h);

        int buf_len = -1;
        if (ioctl(fd, BIOCGBLEN, &buf_len) == -1) {
            orion_log_errno("ioctl(BIOCGBLEN)");
            pcap_close(handle->pcap_h);  /* treat this as a fatal error */
            return -1;
        }

        if (buf_len != ARGOS_CAP_BPF_BUFSIZE) {
            orion_log_warn("requested %u byte BPF buffer; received %u bytes",
                ARGOS_CAP_BPF_BUFSIZE, buf_len);
        } else {
            orion_log_info("requested and received %u byte BPF buffer", buf_len);
        }

#if ARGOS_CAP_SET_BIOCIMMEDIATE
        int yes = 1;
        if ((rv = ioctl(fd, BIOCIMMEDIATE, &yes)) == -1)
            orion_log_errno("ioctl(BIOCIMMEDIATE)");
        else if (rv != 0)
            orion_log_warn("ioctl(BIOCIMMEDIATE) returns %d", rv);
#endif /* #if ARGOS_CAP_SET_BIOCIMMEDIATE */
    }

    handle->pcap_fd = pcap_get_selectable_fd(handle->pcap_h);
    if (handle->pcap_fd < 0) {
        orion_log_err("pcap_get_selectable_fd returned %d", handle->pcap_fd);
        handle->pcap_fd = 0;
        pcap_close(handle->pcap_h);
        return -1;
    }

    rv = async_add_read_fd(handle->pcap_fd, ARGOS_CAP_PCAP_ASYNCPRIO,
        handle->readable, pcap_read_cb, handle);
    if (rv != 0) {
        orion_log_errno("async_add_read_fd");
        pcap_close(handle->pcap_h);
        return -1;
    }

    orion_log_debug("opened %s pcap", (handle->is_offline ? "offline" : "live"));
    return 0;
}

/* async loop callback */
static void
pcap_read_cb(int fd, void *user)
{
    struct argos_capture_hdl *handle = (struct argos_capture_hdl*)user;

    handle->capt_pkts = 0;
    handle->capt_bytes = 0;

    /*
     * from pcap(3):
     *
     * A cnt of -1 processes all the packets received in one buffer when read-
     * ing  a  live  capture,  or  all  the packets in the file when reading a
     * ``savefile''.
     */
    int cnt = handle->is_offline ? 512 : -1;
    int rv = pcap_dispatch(handle->pcap_h, cnt, handle_packet, user);

    if (rv != -1) {
        if (handle->capt_pkts >= DISPATCH_LOG_MIN) {
            orion_log_debug("pcap_dispatch captured %u packets (%u bytes)",
                handle->capt_pkts, handle->capt_bytes);
        }
    }

    switch (rv) {
    case -2:  /* pcap_breakloop called */
        break;

    case -1:  /* pcap error */
        orion_log_err("pcap_dispatch: %s", pcap_geterr(handle->pcap_h));
        break;

    case 0:  /* end of file reached or read timeout before any captures */
        if (handle->is_offline) {
            orion_log_info("end of pcap file reached");
            argos_capture_close(handle);

            /* call packet handler with NULL header & packet to signal EOF */
            handle->pkt_func(NULL, NULL, handle->user);
        }
        break;

    default:  /* yay - some packets were captured */
        assert(rv > 0);
        break;
    }
}
