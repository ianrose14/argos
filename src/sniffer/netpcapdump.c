/*
 * Author: Ian Rose
 * Date Created: Nov 14, 2009
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <math.h>
#include <paths.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap/pcap.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <net/if.h>  /* must be included before net80211/ieee80211_ioctl.h */
#include <net80211/ieee80211_ioctl.h>

/* local includes */
#include "async.h"
#include "buffer.h"
#include "quicklz.h"
#include "argos/capture.h"
#include "argos/common.h"
#include "argos/net.h"
#include "argos/sniffer.h"
#include "orion/config.h"
#include "orion/fs.h"
#include "orion/log.h"
#include "orion/net.h"
#include "orion/string.h"
#include "orion/time.h"

/*
 * TODOs
 *
 * - much of the server-mode's network logic should be moved into net.c (not
 * high priority)
 */

/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

#define PROGNAME "netpcapdump"
#define DEF_CONFIGFILE "netpcapdump.cfg"
#define DEF_LOGNAME "netpcapdump.log"
#define DEF_LOGDIR "logs"
#define DEF_PCAPDIR "pcaps"
#define DEF_PORTNO 9699


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct conn_state {
    int fd;
    struct sockaddr_in addr;
    char *hostname;
    struct buffer *inbuf;
    struct buffer *pktbuf;
    pcap_t *pcap;
    pcap_dumper_t *dumper;
    struct tm dump_opened;
    uint8_t last_channel;
};

enum channel_rotation {
    CHANNEL_ROTATE_NONE,
    CHANNEL_ROTATE_FIXED,
    CHANNEL_ROTATE_PROPORTIONAL
};


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* capture handle (essentially a wrapped pcap descriptor) */
static struct argos_capture_hdl *capture_h = NULL;

/* network connection to the server */
static struct argos_net_conn *server_conn = NULL;

/* datalinktype name */
static const char *dlt_name = ARGOS_DEF_DLTNAME;

/* how often to send stats messages to the server (in seconds) */
static int send_stats_interval = 0;

/* packets received from libpcap */
static uint32_t pkts_recv = 0;

/* if non-0, then the userid that we should drop permissions to when possible */
static uid_t uid = 0;

/* capturing interface */
const char *if_name = ARGOS_DEF_IFNAME;

/* channel rotation policy */
static enum channel_rotation chan_rotation = CHANNEL_ROTATE_NONE;
static uint32_t chan_rotation_ival_ms;

/* current and last channel */
static uint8_t cur_channel = 0;
static uint8_t last_channel = 0;
static struct timeval last_channel_change = {0, 0};
static uint8_t first_channel = 0;

/* packet counts, dwell time, assigned time per channel */
static uint32_t channel_counts[MAX_80211G_CHANNEL];
static uint32_t channel_elapsed_ms[MAX_80211G_CHANNEL];
static uint32_t channel_share_ms[MAX_80211G_CHANNEL];

/* where pidfiles go (default: current directory) */
static char *pidhome = ".";

/* where pcap dumpfiles go (for server mode) */
static char pcapdir[ARGOS_MAX_PATH_LEN+1];

/* when the pcap descriptor was opened */
static struct timeval pcap_opened;


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void accept_cb(int fd, void *user);

static void become_root(void);

static void change_channel(uint8_t channel);

static void channel_rotate_evt(void *user);

static void corefile_check(const char *filename);

static ssize_t decompress_packets(uint8_t algorithm, const u_char *inptr,
    uint32_t len, u_char *outptr, uint32_t orig_len);

static void disconnect_client(struct conn_state *conn);

/* callback for capture.c */
static void handle_captured_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

/* callback for net.c */
static void handle_change_channel(uint16_t channel, void *user);

/* callback for net.c */
static void handle_connected(struct argos_net_conn *conn, void *user);

static void handle_network_packet(struct conn_state *conn, const struct pcap_pkthdr *h,
    const u_char *sp, uint8_t channel);

/* callback for net.c */
static void handle_server_error(uint16_t errnum, const char *msg, void *user);

static void init_channel_rotation(const struct orion_config_file *conf);

static void init_logging(const struct orion_config_file *conf, int force_debug,
    int daemonized);

static void init_net(const struct orion_config_file *conf, int portno,
    u_char as_server);

static void init_uid(const struct orion_config_file *conf);

static int pcap_readable(int fd, void *user);

static int process_buffer(struct conn_state *conn, struct buffer *b);

static void read_cb(int fd, void *user);

static void release_root(void);

static void send_stats_evt(void *user);

static void setup_running_state(int daemonize);

static void signal_handler(int signum);


/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    /* default values for command line arguments */
    const char *configfile = DEF_CONFIGFILE;
    int daemonize = 0;
    int portno = 0;
    u_char force_debug = 0;
    u_char run_server = 0;
    u_char has_client_opts = 0;

    /* process command line options */
    const char *usage =
        "usage: " PROGNAME " [-dgRsv] [-c config] [-i interface] [-p portno] [-P pidhome] [-y datalinktype]\n";

    int c;
    while ((c = getopt(argc, argv, ":c:dghi:p:P:svy:")) != -1) {
        switch (c) {
        case 'c':
            configfile = optarg;
            break;
        case 'd':
            daemonize = 1;
            break;
        case 'g':
            force_debug = 1;
            break;
        case 'h':
            printf(usage);
            printf("\n"
                "options:\n"
                "    -c  specify configuration file\n"
                "    -d  daemonize\n"
                "    -g  enable debugging output\n"
                "    -h  print usage information and quit\n"
                "    -i  network interface on which to capture packets"
                " (default: %s)\n"
                "    -p  specify a server port to connect to or listen on\n"
                "    -P  write pidfiles to specified directory\n"
                "    -s  run as server\n"
                "    -v  print version information and quit\n"
                "    -y  datalink type for capturing interface (default: %s)\n",
                ARGOS_DEF_IFNAME, ARGOS_DEF_DLTNAME);
            exit(0);
            break;
        case 'i':
            if_name = optarg;
            has_client_opts = 1;  /* 'i' option is only valid in client mode */
            break;
        case 'p':
            portno = atoi(optarg);
            break;
        case 'P':
            pidhome = optarg;
            break;
        case 's':
            run_server = 1;
            break;
        case 'v':
            printf("Argos network dumper version %d.%02d  (built %s %s)\n",
                ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION, __DATE__, __TIME__);
            exit(0);
        case 'y':
            dlt_name = optarg;
            has_client_opts = 1;  /* 'y' option is only valid in client mode */
            break;
        case ':':
            errx(1, "option -%c requires an operand", optopt);
            break;
        case '?':
            errx(1, "unrecognized option: -%c", optopt);
            break;
        default:
            /* unhandled option indicates programming error */
            assert(0  /* unhandled option */);
        }
    }

    if (optind != argc)
        errx(1, "program does not take arguments");

    /* some options are only valid in client mode */
    if (run_server && has_client_opts)
        errx(1, "-i and -y options are incompatible with -s option");

    /* set up signal handlers */
    if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
        signal(SIGHUP, signal_handler);

    if (signal(SIGINT, SIG_IGN) != SIG_IGN)
        signal(SIGINT, signal_handler);

    if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
        signal(SIGTERM, signal_handler);

    /* handle daemonizing and/or pidfile */
    setup_running_state(daemonize);

    /* initialize all channel counts to 0 */
    for (int i=0; i < MAX_80211G_CHANNEL; i++)
        channel_counts[i] = 0;

    /*
     * Initialize various things from the configuration file.  The order that
     * these are handled is very important.  First, the username entry must be
     * handled (if present) because that will affect the owner of any files that
     * are created subsequently.  Next, logging needs to be set up so that the
     * orion_log_xxx methods actually do something.  And lastly, all other
     * parameters can be handled in any order.
     */
    struct orion_config_file *conf = orion_config_open(configfile);
    if (conf == NULL) {
        err(1, "orion_config_open(%s) at %s line %d", configfile,
            basename(__FILE__), __LINE__);
    }

    init_uid(conf);
    init_logging(conf, force_debug, daemonize);

    /* logging works at this point */
    char invocation[256] = "";
    for (int i=0; i < argc; i++) {
        strlcat(invocation, argv[i], sizeof(invocation));
        strlcat(invocation, " ", sizeof(invocation));
    }

    orion_log_info(PROGNAME " starting up, version %d.%02d  (built %s %s)",
        ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION, __DATE__, __TIME__);
    orion_log_info("invoked as %s", invocation);
    orion_log_info("config file: %s", configfile);
    orion_log_flush();

    if (!run_server) {
        /* set up packet capturing */
        cur_channel = orion_net_get_channel(if_name);
        if (cur_channel == 0)
            err(1, "orion_net_get_channel at %s line %d", basename(__FILE__),
                __LINE__);

        int dlt = pcap_datalink_name_to_val(dlt_name);
        if (dlt < 0)
            errx(1, "invalid data link type: %s", dlt_name);

        int snaplen = orion_config_get_int(conf, "snaplen", ARGOS_DEF_SNAPLEN);

        capture_h = argos_capture_create_live(if_name, dlt, snaplen,
            handle_captured_packet, NULL, pcap_readable);
        if (capture_h == NULL)
            err(1, "argos_capture_create_live");

        orion_log_info("interface=%s, snaplen=%u, dlt=%s", if_name, snaplen,
            pcap_datalink_val_to_name(dlt));

        /* how often to send stats messages to the server (in seconds) */
        send_stats_interval = orion_config_get_int(conf, "stats_interval",
            ARGOS_DEF_STATS_INTERVAL);
        orion_log_info("send-stats-interval=%d", send_stats_interval);

        /* set up channel rotation parameters from configuration file */
        init_channel_rotation(conf);
        if (chan_rotation == CHANNEL_ROTATE_NONE)
            orion_log_info("channel-rotation=None");
        else if (chan_rotation == CHANNEL_ROTATE_FIXED)
            orion_log_info("channel-rotation=Fixed (interval=%u ms)",
                chan_rotation_ival_ms);
        else if (chan_rotation == CHANNEL_ROTATE_PROPORTIONAL)
            orion_log_info("channel-rotation=Proportional (interval=%u ms)",
                chan_rotation_ival_ms);
        else
            abort();
    }

    /*
     * network initialization must occur AFTER capturing is set up because we
     * need to know our DLT value (for client mode, at least)
     */
    init_net(conf, portno, run_server);

    orion_config_close(conf);  /* done with configuration file */

    if (!run_server) {
        /*
         * if stats-sending is enabled at all (interval != 0), call
         * send_stats_evt right away because its first execution just
         * initializes static fields but doesn't actually compute or output
         * stats; it will resechedule itself to run every [send_stats_interval]
         * seconds
         */
        if (send_stats_interval > 0)
            send_stats_evt(NULL);

        /*
         * Change to the initial channel and then, if any channel-rotation
         * policy is enabled, schedule the first channel-rotate event
         */
        change_channel(cur_channel);
        channel_rotate_evt(NULL);
    }

    /* kick off the async loop */
    orion_log_info("entering async loop...");
    orion_log_flush();

    int rv = async_loop();
    if (rv == -1) {
        orion_log_crit_errno("async_loop");
    } else if (rv == -2) {
        orion_log_info("async_loop terminated by async_breakloop");
    } else {
        orion_log_info("async_loop terminated on its own");
    }

    orion_log_flush();
    orion_log_info("terminating packet capture");

    if (!run_server) {
        become_root();
        argos_capture_close(capture_h);
        release_root();

        argos_net_close(server_conn);
        server_conn = NULL;
    }

    /* delete pidfile */
    if (daemonize) {
        char pidfile[512] = "";
        strlcpy(pidfile, pidhome, sizeof(pidfile));
        strlcat(pidfile, "/" PROGNAME ".pid", sizeof(pidfile));
        if (unlink(pidfile) != 0)
            orion_log_errnof("unlink(%s)", pidfile);
    }

    orion_log_info(PROGNAME " exitting cleanly");
    orion_log_flush();

    /*
     * flush and close log to make sure everything gets written to disk; send
     * errors to warn() since the argos log isn't available (we're closing it!)
     */
    if (orion_log_close() == -1)
        warn("orion_log_close");

    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

static void
accept_cb(int fd, void *user)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int cli_fd = accept(fd, (struct sockaddr*)&addr, &len);
    if (cli_fd == -1) err(1, "accept");

    char hostname[NI_MAXHOST] = "";

    int rv = getnameinfo((const struct sockaddr*)&addr, sizeof(struct sockaddr),
        hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);

    if (rv == 0) {
        for (size_t i=0; i < strlen(hostname); i++) {
            /* simplify hostname by truncated junk at the end */
            if (hostname[i] == '.') {
                hostname[i] = '\0';
                break;
            }
        }

        if (strlen(hostname) == 0) {
            hostname[0] = '?';
            hostname[1] = '\0';
        }
    } else {
        orion_log_err("failed to lookup IP %s: %s", inet_ntoa(addr.sin_addr),
            gai_strerror(rv));
        strncpy(hostname, inet_ntoa(addr.sin_addr), sizeof(hostname));
    }

    orion_log_info("accepted connection from %s (%s)",
        inet_ntoa(addr.sin_addr), hostname);

    struct conn_state *conn = malloc(sizeof(struct conn_state));
    if (conn == NULL)
        err(1, "malloc");

    bzero(conn, sizeof(struct conn_state));
    conn->fd = cli_fd;
    memcpy(&conn->addr, &addr, sizeof(addr));
    conn->hostname = strdup(hostname);
    conn->inbuf = buffer_create((1024+102)*1024);
    if (conn->inbuf == NULL) err(1, "buffer_create");
    conn->pktbuf = buffer_create((1024+102)*1024);
    if (conn->pktbuf == NULL) err(1, "buffer_create");

    rv = async_add_read_fd(cli_fd, 0, async_true_check, read_cb, conn);
    if (rv == -1)
        err(1, "async_add_read_fd");
}

static void
become_root(void)
{
    if (uid != getuid()) {
        if (seteuid(0) == -1) {
            orion_log_crit_errno("seteuid(0)");
            abort();
        }
    }
}

static void
change_channel(uint8_t channel)
{
    assert(channel > 0);
    assert(channel <= MAX_80211G_CHANNEL);

    if (channel == cur_channel) return;

    /* restore permissions if they were dropped previously */
    become_root();

    /*
     * for efficiency, we look up the ieee80211_channel struct that corresponds
     * to each channel ahead of time (instead of every time this function is
     * called)
     */
    static int sock;
    static struct ieee80211_channel channel_info[MAX_80211G_CHANNEL];
    static uint8_t need_initialize = 1;

    if (need_initialize) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) err(1, "socket");

        struct ieee80211req_chaninfo chaninfo;

        struct ieee80211req ireq;
        memset(&ireq, 0, sizeof(ireq));
        strlcpy(ireq.i_name, if_name, sizeof(ireq.i_name));
        ireq.i_type = IEEE80211_IOC_CHANINFO;
        ireq.i_data = (void*)(&chaninfo);
        ireq.i_len = sizeof(chaninfo);
        
        if (ioctl(sock, SIOCG80211, &ireq) < 0)
            err(1, "ioctl(SIOCG80211) failed for IEEE80211_IOC_CHANINFO");

        for (u_int i = 0; i < chaninfo.ic_nchans; i++) {
            const struct ieee80211_channel *c = &chaninfo.ic_chans[i];
            /*
             * note that we do not mask ic_flags (and thus an exact match is
             * required) - this excludes 'TURBO' channels
             */
            if (c->ic_flags == IEEE80211_CHAN_G) {
                int chan = c->ic_ieee;
                if (chan <= MAX_80211G_CHANNEL)
                    memcpy(&channel_info[chan-1], c, sizeof(struct ieee80211_channel));
            }
        }

        for (int i=0; i < MAX_80211G_CHANNEL; i++) {
            if (channel_info[i].ic_ieee == 0)
                errx(1, "no channel info found for channel %d", i);
        }

        need_initialize = 0;
    }

    struct timeval start;
    if (gettimeofday(&start, NULL) != 0)
        err(1, "gettimeofday");

    struct ieee80211req ireq;
    memset(&ireq, 0, sizeof(ireq));
    strlcpy(ireq.i_name, if_name, sizeof(ireq.i_name));
    ireq.i_type = IEEE80211_IOC_CURCHAN;
    ireq.i_val = 0;
    ireq.i_len = sizeof(struct ieee80211_channel);
    ireq.i_data = &channel_info[channel-1];
    if (ioctl(sock, SIOCS80211, &ireq) < 0)
        err(1, "ioctl(SIOCS80211) failed for IEEE80211_IOC_CURCHAN");

    struct timeval end;
    if (gettimeofday(&end, NULL) != 0)
        err(1, "gettimeofday");

    if (cur_channel != 0) {
        struct timeval dur;
        orion_time_subtract(&start, &last_channel_change, &dur);
        channel_elapsed_ms[cur_channel-1] += (dur.tv_sec*1000 + (dur.tv_usec+500)/1000);
    }

    cur_channel = channel;

    /* drop permissions if we can */
    release_root();

    orion_log_debug("channel change took %llu microseconds",
        timeval2usec(end) - timeval2usec(start));
}

static void
channel_rotate_evt(void *user)
{
    if (chan_rotation == CHANNEL_ROTATE_NONE) {
        change_channel(first_channel);
        return;
    }

    uint8_t next_channel;

    static u_char first_exec = 1;
    if (first_exec) {
        next_channel = first_channel;

        if (chan_rotation == CHANNEL_ROTATE_FIXED) {
            /*
             * essentially just divide the channel-rotation interval evenly
             * across all of the channels, but this way takes care of any
             * leftover milliseconds that do not divide evenly
             */
            uint32_t time_left = chan_rotation_ival_ms;
            for (int i=0; i < MAX_80211G_CHANNEL; i++) {
                int chans_left = MAX_80211G_CHANNEL - i;
                uint32_t share = round((double)time_left/chans_left);
                time_left -= share;
                channel_share_ms[i] = share;
            }
        }
        else if (chan_rotation == CHANNEL_ROTATE_PROPORTIONAL) {
            // todo
        }
        else
            abort();

        first_exec = 0;
    } else {
        next_channel = cur_channel + 1;
        if (next_channel > MAX_80211G_CHANNEL) {
            next_channel = 1;

            if (chan_rotation == CHANNEL_ROTATE_PROPORTIONAL) {
                // todo - recalc shares
                (void)channel_elapsed_ms;
            }
        }
    }

    /*
     * reschedule for [this channel's share-time] from now.
     * note: we do not use relative scheduling, thus allowing slippage (but
     * ensuring that each channel gets at least its allotted time)
     */
    uint32_t dur = channel_share_ms[next_channel-1];
    if (async_schedule_usec(dur*(u_long)1000, channel_rotate_evt, user, 1) == NULL)
        orion_log_errno("async_schedule(channel_rotate_evt)");

    change_channel(next_channel);
}

static void
corefile_check(const char *filename)
{
    struct stat sb;
    if (stat(filename, &sb) == -1) {
        if (errno == ENOENT)
            ; /* file does not exist - this is fine */
        else
            /* some other (real) error */
            orion_log_errno("stat");
        return;
    }

    char cbuf[128];
    snprintf(cbuf, sizeof(cbuf), "%s exists, created at %d", filename,
        sb.st_birthtime);

    orion_log_info("%s", cbuf);

    ssize_t len = argos_net_send_errmsg(server_conn, 0, cbuf);
    if (len == -1) {
        orion_log_crit_errno("argos_net_send_errmsg");
    }
}

static ssize_t
decompress_packets(uint8_t algorithm, const u_char *inptr, uint32_t inlen,
    u_char *outptr, uint32_t orig_len)
{
    char *alg_name;
    uint32_t outlen = 0;

    switch (algorithm) {
    case ARGOS_NET_COMPRESS_NONE:
        alg_name = "memcpy";
        memcpy(outptr, inptr, inlen);
        outlen = inlen;
        break;

    /* note - LZO not supported */
    
    case ARGOS_NET_COMPRESS_QUICKLZ: {
        alg_name = "QuickLZ";
        static char qlz_scratch[QLZ_SCRATCH_DECOMPRESS];
        outlen = qlz_decompress((const char*)inptr, outptr, qlz_scratch);
        break;
    }
    default:
        errno = EINVAL;
        return -1;
    }

    if (outlen != orig_len) {
        /* uh oh - this is bad */
        orion_log_err("[%s] decompression returned %u bytes, expected %u",
            alg_name, orig_len, outlen);
        errno = EPROTO;
        return -1;
    }

    return orig_len;
}

static void
disconnect_client(struct conn_state *conn)
{
    int rv = async_remove_fd(conn->fd);
    assert(rv == 0);
    close(conn->fd);
    free(conn->hostname);
    buffer_destroy(conn->inbuf);
    buffer_destroy(conn->pktbuf);
    if (conn->pcap != NULL) pcap_close(conn->pcap);
    if (conn->dumper != NULL) pcap_dump_close(conn->dumper);
    free(conn);
}

static void
handle_captured_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    pkts_recv++;

    /* could do some better estimation here... */
    uint8_t capture_channel;

    if (orion_time_cmp(&h->ts, &last_channel_change) <= 0)
        capture_channel = last_channel;
    else
        capture_channel = cur_channel;

    channel_counts[capture_channel-1]++;

    /* push packet down to be enqueued by the network component */
    ssize_t len = argos_net_send_packet(server_conn, h, sp, capture_channel);

    if (len == -1) {
        if (errno == ENOBUFS) {
            /* shouldn't happen if capture component is checking pcap_readable */
            orion_log_warn_errno("argos_net_send_packet");
        } else {
            /* this indicates some kind of operational error (probable bug) */
            orion_log_crit_errno("argos_net_send_packet");
            async_breakloop();
        }
    }
}

static void
handle_change_channel(uint16_t channel, void *user)
{
    (void) user;  /* unused */

    if (channel > ARGOS_NET_MAX_CHAN) {
        orion_log_err("invalid argument to handle_change_channel: %hu", channel);
        return;
    }

    orion_log_debug("change_channel(%hu) request received", channel);
    change_channel(channel);
}

static void
handle_connected(struct argos_net_conn *conn, void *user)
{
    (void) conn;  /* unused */
    (void) user;  /* unused */

    /*
     * check for a corefile from a previous execution, and send an error
     * message to the server if one is found
     */
    corefile_check(PROGNAME ".core");

    /*
     * this program does not use the set-BPF network command; it just starts
     * capturing immediately upon connecting.
     */
    if (capture_h->pcap_h == NULL) {
        become_root();
        if (argos_capture_set_filter(capture_h, "") == -1)
            abort();
        gettimeofday(&pcap_opened, NULL);
        release_root();
    }
}

static void
handle_network_packet(struct conn_state *conn, const struct pcap_pkthdr *h,
    const u_char *sp, uint8_t channel)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    /* is it time to rotate the dumpfile? */
    struct tm tm_now;
    localtime_r(&now.tv_sec, &tm_now);

    if ((conn->dumper == NULL) ||
        (tm_now.tm_year > conn->dump_opened.tm_year) ||
        (tm_now.tm_mon > conn->dump_opened.tm_mon) ||
        (tm_now.tm_mday > conn->dump_opened.tm_mday) ||
        (tm_now.tm_hour > conn->dump_opened.tm_hour)) {

        if (conn->dumper != NULL)
            pcap_dump_close(conn->dumper);

        char *path;
        if (asprintf(&path, "%s/%04d/%02d/%02d/%02d-%s.pcap", pcapdir,
                tm_now.tm_year + 1900, tm_now.tm_mon + 1,
                tm_now.tm_mday, tm_now.tm_hour, conn->hostname) == -1)
            err(1, "asprintf");

        /* create directory path (if needed) */
        if (orion_fs_mkdirs(dirname(path), S_IRWXU) == -1)
            err(1, "orion_fs_mkdirs");

        assert(conn->pcap != NULL);
        conn->dump_opened = tm_now;
        conn->dumper = pcap_dump_open(conn->pcap, path);
        free(path);
    }

    /* write packet to dumpfile */
    pcap_dump((u_char*)conn->dumper, h, sp);

    /* if channel changed since the last packet, log that */
    if (channel != conn->last_channel) {
        orion_log_info("CHANNEL host=%s channel=%d ts=%u.%06u", conn->hostname,
            channel, h->ts.tv_sec, h->ts.tv_usec);
        conn->last_channel = channel;
    }
}

static void
handle_server_error(uint16_t errnum, const char *msg, void *user)
{
    orion_log_err("[server] %s (%s)", strerror(errnum), msg);

    /* be very defensive for now; all errors cause the program to quit */
    async_breakloop();
}

/* set up channel rotation from configuration file settings */
static void
init_channel_rotation(const struct orion_config_file *conf)
{
    /* starting_channel */
    first_channel = (uint8_t)orion_config_get_int(conf, "starting_channel", 1);

    /* channel_rotation */
    const char *rot_desc = orion_config_get_str(conf, "channel_rotation", NULL);
    if (rot_desc != NULL) {
        if ((strcasecmp(rot_desc, "none") == 0) || (strcasecmp(rot_desc, "0") == 0))
            chan_rotation = CHANNEL_ROTATE_NONE;

        else if (strcasecmp(rot_desc, "fixed") == 0)
            chan_rotation = CHANNEL_ROTATE_FIXED;

        else if (strcasecmp(rot_desc, "proportional") == 0)
            chan_rotation = CHANNEL_ROTATE_PROPORTIONAL;
    }

    /* channel_rotation_interval */
    double val = orion_config_get_double(conf, "channel_rotation_interval",
        0.1*MAX_80211G_CHANNEL);
    chan_rotation_ival_ms = (int)round(1000*val);
}

/* set up logging from configuration file settings */
static void
init_logging(const struct orion_config_file *conf, int force_debug, int daemonized)
{
    /* force_debug_logging variable can override config file setting */
    if (force_debug) {
        orion_log_set_level(ORION_LOG_DEBUG);
    } else {
        /* loglevel */
        const char *loglevel = orion_config_get_str(conf, "loglevel", NULL);
        if (loglevel != NULL) {
            enum orion_log_level lvl = orion_log_lookup_level(loglevel);
            if (lvl == -1)
                errx(1, "invalid loglevel parameter value: \"%s\"", loglevel);
            orion_log_set_level(lvl);
        }
    }

    /* open argos log (destination depends on whether we daemonized) */
    if (daemonized) {
        /* logname */
        const char *raw_logname = orion_config_get_str(conf, "logname",
            DEF_LOGNAME);

        /* logdir */
        const char *raw_logdir = orion_config_get_str(conf, "logdir",
            DEF_LOGDIR);

        /*
         * pass each variable through a shell (e.g. to resolve environment
         * variables)
         */
        char logname[ARGOS_MAX_PATH_LEN+1];
        char logdir[ARGOS_MAX_PATH_LEN+1];

        ssize_t rv = orion_str_unshellify(raw_logname, logname, sizeof(logname));
        if (rv == -1) err(1, "invalid 'logname' configuration entry");

        rv = orion_str_unshellify(raw_logdir, logdir, sizeof(logdir));
        if (rv == -1) err(1, "invalid 'logdir' configuration entry");

        if (orion_log_open(logdir, logname) == -1)
            err(1, "orion_log_open at %s line %d", basename(__FILE__), __LINE__);
    } else {
        if (setlinebuf(stdout) != 0)
            err(1, "setlinebuf at %s line %d", basename(__FILE__), __LINE__);

        if (orion_log_fopen(stdout) == -1)
            err(1, "orion_log_fopen at %s line %d", basename(__FILE__), __LINE__);
    }

    /* figure out where to store pcap files (only used in server mode) */

    /* pcapdir */
    const char *raw_pcapdir = orion_config_get_str(conf, "pcapdir", DEF_PCAPDIR);

    /* pass variable through a shell (e.g. to resolve environment variables) */
    ssize_t rv = orion_str_unshellify(raw_pcapdir, pcapdir, sizeof(pcapdir));
    if (rv == -1) err(1, "invalid 'pcapdir' configuration entry");
}

/* create a network connection according to configuration file settings */
static void
init_net(const struct orion_config_file *conf, int portno, u_char as_server)
{
    if (portno == 0)
        portno = orion_config_get_int(conf, "server_port", DEF_PORTNO);

    if (as_server) {
        struct addrinfo hints, *servinfo;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        char portstr[32];
        snprintf(portstr, sizeof(portstr), "%d", portno);

        int rv = getaddrinfo(NULL, portstr, &hints, &servinfo);
        if (rv != 0)
            errx(1, "getaddrinfo: %s", gai_strerror(rv));

        /* if getaddrinfo returns 0, it should return a list of addrinfo structs */
        assert(servinfo != NULL);
        assert(servinfo->ai_addrlen <= sizeof(struct sockaddr_in));

        struct sockaddr_in addr;
        memcpy(&addr, servinfo->ai_addr, servinfo->ai_addrlen);
        freeaddrinfo(servinfo);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) err(1, "socket");

        int on = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
            err(1, "setsockopt(SO_REUSEADDR)");

        if (bind(sock, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
            err(1, "bind");

        if (listen(sock, 5) < 0)
            err(1, "listen");

        orion_log_info("listening for connections on %s:%d",
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        rv = async_add_read_fd(sock, 0, async_true_check, accept_cb, NULL);
        if (rv == -1)
            err(1, "async_add_read_fd");
    } else {
        /* as client */
        const char *hostname = orion_config_get_str(conf, "server_hostname",
            ARGOS_NET_DEF_SERVER_HOSTNAME);

        struct sockaddr_in sin;
        if (orion_net_lookup_inaddr(hostname, portno, SOCK_STREAM, &sin) == -1)
            err(1, "orion_net_lookup_inaddr");

        orion_log_info("server: %s:%d", hostname, portno);

        /* have to initialize network component before creating connection object */
        if (argos_net_init() != 0)
            err(1, "argos_net_init");

        int inbufsz = orion_config_get_int(conf, "net_inbuf_kb",
            ARGOS_DEF_NET_INBUF_KB);
        int outbufsz = orion_config_get_int(conf, "net_outbuf_kb",
            ARGOS_DEF_NET_OUTBUF_KB);
        int pktbufsz = orion_config_get_int(conf, "net_pktbuf_kb",
            ARGOS_DEF_NET_PKTBUF_KB);

        server_conn = argos_net_client_create(&sin, capture_h->dlt, NULL,
            inbufsz*1024, outbufsz*1024, pktbufsz*1024);
        if (server_conn == NULL)
            err(1, "argos_net_client_create");

        orion_log_debug("network buffers (KB):  inbuf=%d outbuf=%d pktbuf=%d",
            inbufsz, outbufsz, pktbufsz);

        argos_net_set_chanhandler(server_conn, handle_change_channel, NULL);
        argos_net_set_connecthandler(server_conn, handle_connected, NULL);
        argos_net_set_errhandler(server_conn, handle_server_error, NULL);
    }
}

/* initialize uid variable by looking up username from config file */
static void
init_uid(const struct orion_config_file *conf)
{
    const char *username = orion_config_get_str(conf, "username", NULL);
    if (username == NULL) return;
    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL)
        errx(1, "unknown user: \"%s\"", username);
    uid = pwd->pw_uid;

    if (uid == getuid()) return;

    /*
     * this is a bit of a hack; need to make sure the system supports coredumps
     * from processes that change user credentials
     */
    int rv = system("sysctl kern.sugid_coredump=1 >/dev/null");

    if (rv == -1)
        err(1, "system at %s line %d", basename(__FILE__), __LINE__);
    else if (rv == 127)
        errx(1, "system at %s line %d: shell execution failed",
            basename(__FILE__), __LINE__);
    else if (rv != 0)
        errx(1, "sysctl at %s line %d: failed", basename(__FILE__), __LINE__);

    /* change to specified user id immediately */
    if (seteuid(uid) == -1)
        err(1, "seteuid at %s line %d", basename(__FILE__), __LINE__);
}

static int
pcap_readable(int fd, void *user)
{
    return (argos_net_queue_room(server_conn) >= (capture_h->snaplen + 256));
}

static int
process_buffer(struct conn_state *conn, struct buffer *b)
{
    /*
     * repeatedly parse messages out of the buffer until its empty or a partial
     * message is encountered
     */
    while (buffer_len(b) >= sizeof(struct argos_net_minimal_msg)) {
        struct argos_net_minimal_msg *header =
            (struct argos_net_minimal_msg *)buffer_head(b);

        uint16_t msgtype = ntohs(header->msgtype);
        uint32_t msglen = ntohl(header->msglen);

        /* check that message type and length are valid */
        if (ARGOS_NET_VALIDATE_MSGTYPE(msgtype) == 0) {
            orion_log_err("invalid message type received (type=%hu, len=%u)"
                " from %s", msgtype, msglen, conn->hostname);
            disconnect_client(conn);
            return -1;
        }

        if (ARGOS_NET_VALIDATE_MSGLEN(msgtype, msglen) == 0) {
            orion_log_err("invalid message len received (type=%hu, len=%u)"
                " from %s", msgtype, msglen, conn->hostname);
            disconnect_client(conn);
            return -1;
        }

        if (msglen > buffer_len(b)) {
            /* entire message not yet received */
            if (msglen > buffer_size(b)) {
                /* error - message is bigger than the entire inbuf */
                orion_log_err("inbuf too small for msgtype=%hu (len=%u)"
                    " from %s", msgtype, msglen, conn->hostname);
                disconnect_client(conn);
                return -1;
            }

            /* wait for more bytes to arrive on socket */
            break;
        }

        /* now to type-specific processing */
        switch (msgtype) {
        case ARGOS_NET_HANDSHAKE_MSGTYPE: {
            /*
             * sanity check: did we already receive a handshake from this
             * sniffer node?
             */
            if (conn->pcap != NULL) {
                orion_log_err("multiple handshake messages received from %s",
                    conn->hostname);
                disconnect_client(conn);
                return -1;
            }

            struct argos_net_handshake_msg *msg =
                (struct argos_net_handshake_msg*)header;

            if (ntohl(msg->magicnum) != ARGOS_NET_MAGICNUM) {
                orion_log_warn("invalid magic-number (0x%X) from %s",
                    ntohl(msg->magicnum), conn->hostname);
                disconnect_client(conn);
                return -1;
            }

            uint32_t maj_v = ntohs(msg->major_version);
            uint32_t min_v = ntohs(msg->minor_version);
            
            if ((maj_v != ARGOS_MAJOR_VERSION) || (min_v != ARGOS_MINOR_VERSION)) {
                orion_log_warn("invalid version (%d.%d) from %s, expected %d.%d",
                    maj_v, min_v, conn->hostname, ARGOS_MAJOR_VERSION,
                    ARGOS_MINOR_VERSION);
                disconnect_client(conn);
                return -1;
            }

            uint32_t dlt = ntohl(msg->dlt);
            conn->pcap = pcap_open_dead(dlt, 2048);
            orion_log_info("valid handshake received from %s", conn->hostname);
            break;
        }

        case ARGOS_NET_PCAP_MSGTYPE: {
            if (conn->pcap == NULL) {
                orion_log_err("pcap message received before handshake from %s",
                    conn->hostname);
                disconnect_client(conn);
                return -1;
            }

            struct argos_net_pcap_msg *msg =
                (struct argos_net_pcap_msg*)header;

            struct pcap_pkthdr h;
            h.ts.tv_sec = ntohl(msg->ts_sec);
            h.ts.tv_usec = ntohl(msg->ts_usec);
            h.caplen = ntohl(msg->caplen);
            h.len = ntohl(msg->pktlen);

            if (h.caplen != (msglen - sizeof(struct argos_net_pcap_msg))) {
                orion_log_err("msg->caplen (%u) != msglen (%u) - struct size (%u) from %s",
                    h.caplen, msglen, sizeof(struct argos_net_pcap_msg),
                    conn->hostname);
                abort();
            }

            u_char *sp = buffer_head(b) + sizeof(struct argos_net_pcap_msg);
            handle_network_packet(conn, &h, sp, msg->channel);
            break;
        }

        case ARGOS_NET_STATS_MSGTYPE: {
            if (conn->pcap == NULL) {
                orion_log_err("pcap message received before handshake from %s",
                    conn->hostname);
                disconnect_client(conn);
                return -1;
            }

            struct argos_net_stats_msg *msg =
                (struct argos_net_stats_msg*)header;

            orion_log_info("STATS host=%s ts=%u.%u dur_ms=%u kern_recv=%u"
                " kern_drop=%u app_recv=%u cpu_usr_ms=%u cpu_sys_ms=%u"
                " max_rss_kb=%u net_sent_kb=%u pcap_opened=%u.%u",
                conn->hostname, ntohl(msg->ts_sec), ntohl(msg->ts_usec),
                ntohl(msg->duration_ms), ntohl(msg->kern_recv),
                ntohl(msg->kern_drop), ntohl(msg->app_recv),
                ntohl(msg->usr_time_ms), ntohl(msg->sys_time_ms),
                ntohl(msg->maxrss_kbytes), ntohl(msg->net_sent_bytes)/1024,
                ntohl(msg->pcap_opened_sec), ntohl(msg->pcap_opened_usec));
            break;
        }

        case ARGOS_NET_ERROR_MSGTYPE: {
            struct argos_net_error_msg *msg =
                (struct argos_net_error_msg*)header;

            uint8_t errnum = msg->errnum;
            size_t hdrlen = sizeof(struct argos_net_error_msg);
            uint16_t slen = ntohl(msg->msglen) - hdrlen;
            char *errmsg = (char*)buffer_head(b) + hdrlen;
            orion_log_warn("error from %s: %d - %.*s", conn->hostname, errnum,
                errmsg, slen);
            break;
        }

        case ARGOS_NET_COMPRESS_MSGTYPE: {
            struct argos_net_compress_msg *msg =
                (struct argos_net_compress_msg*)header;

            uint32_t origlen = ntohl(msg->orig_len);

            buffer_compact(conn->pktbuf);
            if (buffer_remaining(conn->pktbuf) < origlen) {
                orion_log_err("pktbuf too small for current contents (%d) plus"
                    " next compression block (%u)", buffer_len(conn->pktbuf),
                    origlen);
                disconnect_client(conn);
                return -1;
            }

            size_t hdrlen = sizeof(struct argos_net_compress_msg);
            size_t blocklen = msglen - hdrlen;

            ssize_t rv = decompress_packets(msg->algorithm, buffer_head(b) + hdrlen,
                blocklen, buffer_tail(conn->pktbuf), origlen);

            if (rv == -1) {
                /* decompression failed */
                orion_log_errnof("%s: decompress_packets", conn->hostname);
                disconnect_client(conn);
                return -1;
            }

            int ret = buffer_expand(conn->pktbuf, rv);
            assert(ret == 0);

            /*
             * now that we have concatenated some more uncompressed packets into
             * conn->pktbuf, process it to try and consume some pcap messages
             */
            if (process_buffer(conn, conn->pktbuf) == -1)
                return -1;  /* packet buffer might fail too */
            
            break;
        }

        default:
            orion_log_err("unsupported message type (%hu) from %s", msgtype,
                conn->hostname);
            disconnect_client(conn);
            return -1;
        }

        int rv = buffer_discard(b, msglen);
        assert(rv == 0);
    }

    return 0;
}

static void
read_cb(int fd, void *user)
{
    struct conn_state *conn = user;

    /* try to ensure at least 32K of recv space */
    if (buffer_remaining(conn->inbuf) < 32*1024)
        buffer_compact(conn->inbuf);

    size_t space = buffer_remaining(conn->inbuf);
    assert(space > 0);

    ssize_t len = recv(fd, buffer_tail(conn->inbuf), space, 0);
    if (len == -1) {
        orion_log_warn("recv from %s: %s", conn->hostname, strerror(errno));
        disconnect_client(conn);
        return;
    }
    else if (len == 0) {
        orion_log_info("EOF received from %s", conn->hostname);
        disconnect_client(conn);
        return;
    }

    int rv = buffer_expand(conn->inbuf, len);
    assert(rv == 0);

    process_buffer(conn, conn->inbuf);
}

static void
release_root(void)
{
    if (uid != 0) {
        if (seteuid(uid) == -1) {
            orion_log_crit_errnof("seteuid(%d)", uid);
            abort();
        }
    }
}

static void
send_stats_evt(void *user)
{
    static u_short first_exec = 1;
    static struct timeval next_time;
    static struct timeval last_time;
    static struct rusage last_rusage;
    static uint32_t last_pkts_recv = 0;

    /* call these as early as possible */
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) {
        orion_log_errno("gettimeofday");
        return;
    }

    struct rusage rusage;
    if (getrusage(RUSAGE_SELF, &rusage) != 0) {
        orion_log_errno("getrusage");
        return;
    }

    struct pcap_stat pcap_stat;
    if (argos_capture_get_stats(capture_h, &pcap_stat) != 0)
        return;

    /* if network connection is shutdown we can't send stats anymore */
    if (server_conn->shutdown) return;

    if (first_exec) {
        last_time = now;
        next_time = now;
        last_rusage = rusage;
    }

    struct timeval elapsed;
    orion_time_subtract(&now, &last_time, &elapsed);
    int duration_ms = 1000*elapsed.tv_sec + (elapsed.tv_usec + 500)/1000;

    /*
     * if this event is more than 50% late, we reschedule relative to the
     * CURRENT time (rather than the scheduled time), allowing schedule
     * slippage.
     */
    if (first_exec || (duration_ms < (1500*send_stats_interval))) {
        next_time.tv_sec += send_stats_interval;
    } else {
        next_time = now;
        next_time.tv_sec += send_stats_interval;
    }

    /* reschedule this function to be called again after another interval */
    if (async_schedule_abs(&next_time, send_stats_evt, user, 1) == NULL)
        orion_log_errno("async_schedule(send_stats_evt)");

    /* on the first execution, just initialize static structs and reschedule */
    if (first_exec) {
        first_exec = 0;
        return;
    }

    /* if pcap descriptor is not open, don't send stats yet */
    if (capture_h->pcap_h == NULL) return;

    long swaps = rusage.ru_nswap - last_rusage.ru_nswap;
    if (swaps > 0)
        orion_log_warn("rusage reports %ld swaps", swaps);

    struct timeval usr_time, sys_time;
    orion_time_subtract(&rusage.ru_utime, &last_rusage.ru_utime, &usr_time);
    orion_time_subtract(&rusage.ru_stime, &last_rusage.ru_stime, &sys_time);

    struct argos_net_stats stats;
    stats.ts = now;
    stats.duration_ms = duration_ms;
    stats.kern_recv = pcap_stat.ps_recv;
    stats.kern_drop = pcap_stat.ps_drop;
    stats.app_recv = pkts_recv - last_pkts_recv;
    stats.usr_time = usr_time;
    stats.sys_time = sys_time;
    stats.maxrss_kbytes = (uint32_t)rusage.ru_maxrss;
    stats.pcap_opened = pcap_opened;

    int len = argos_net_send_stats(server_conn, &stats);

    if (len == -1) {
        if (errno == ENOBUFS) {
            /*
             * since stats messages are sent quite rarely, this error should
             * generally only happen if our network output is having serious issues
             */
            orion_log_warn_errno("argos_net_send_stats");
        } else {
            /* this indicates some kind of operational error (probable bug) */
            orion_log_crit_errno("argos_net_send_stats");
            async_breakloop();
        }
    }

    last_time = now;
    last_rusage = rusage;
    last_pkts_recv = pkts_recv;
}

static void
setup_running_state(int daemonize)
{
    if (!daemonize) return;

    char pidfile[512] = "";
    strlcpy(pidfile, pidhome, sizeof(pidfile));
    strlcat(pidfile, "/" PROGNAME ".pid", sizeof(pidfile));

    int pidfd = orion_fs_open_pidfile(pidfile);
    if (pidfd == -1) {
        err(1, "orion_fs_open_pidfile at %s line %d",
            basename(__FILE__), __LINE__);
    } else if (pidfd == -2) {
        /* according to pidfile, process is already running */
        errx(1, "process already running");
    }

    FILE *pidhandle = fdopen(pidfd, "w");
    if (pidhandle == NULL)
        err(1, "fdopen at %s line %d", basename(__FILE__), __LINE__);

    int fd = open(_PATH_DEVNULL, O_RDWR, 0);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    /* keep stderr if possible (i.e. its not a tty) */
    if (isatty(STDERR_FILENO)) dup2(fd, STDERR_FILENO);
    close(fd);

    if (daemon(1 /* don't chdir */, 1 /* don't redirect fds */) == -1)
        err(1, "daemon at %s line %d", basename(__FILE__), __LINE__);

    /* now that we have our final pid, write it to the pidfile */
    if (fprintf(pidhandle, "%d\n", getpid()) < 0)
        err(1, "fprintf to pidfile");
    if (fclose(pidhandle) < 0)
        err(1, "fclose on pidfile");
}

static void
signal_handler(int signum)
{
    /* number of SIGTERM/SIGINT signals received */
    static int quit_requests = 0;

    /*
     * helps for debugging - we use stderr instead of writing to the log because
     * the log might come out weird if we did (e.g. if the signal occurred
     * half-way through printing a sentence to the log then the resulting text
     * will be a little mixed up).
     */
    time_t now = time(NULL);
    char timestamp[32];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0';

    if ((signum == SIGINT) || (signum == SIGTERM)) {
        fprintf(stderr, "%s   caught signal %d\n", timestamp, signum);
        fflush(stderr);

        quit_requests++;

        if (quit_requests == 1) {
            /*
             * Break out of async_loop().  Note that if we are in the middle of
             * a call to pcap_dispatch() it might take a while before
             * async_loop() actually terminates.
             *
             * Note that async_breakloop() just sets a flag and thus is safe to
             * call from inside a signal handler.
             */
            async_breakloop();
        } else {
            /* there have been multiple "quit" signals; force exit */
            orion_log_warn("force quit from signal %d", signum);
            orion_log_close();
            fprintf(stderr, "%s   force quit from signal %d\n", timestamp, signum);
            fflush(stderr);
            exit(1);
        }
    }
    else if (signum == SIGHUP) {
        fprintf(stderr, "%s   caught signal %d\n", timestamp, signum);
        fflush(stderr);

        /*
         * flush logfile - we do this immediately (from the signal
         * handler) instead of setting a flag and handling it later for
         * robustness; if things get stuck such that we never get back to the
         * code that checks the 'do-flush' flag, then we would be unable to
         * flush the log to (hopefully) figure out what went wrong
         */
        orion_log_flush();
    } else {
        /* bad signal received */
        assert(0  /* invalid signal */);
    }
}
