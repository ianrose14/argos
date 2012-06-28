/*
 * Author: Ian Rose
 * Date Created: Sep 1, 2008
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/bpf.h>   /* must include before pcap/pcap.h */
#include <pcap/pcap.h>

/* local includes */
#include "async.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

/* behavior */
#define SET_BIOCIMMEDIATE 1
#define SET_PCAP_NONBLOCK 1
#define MODE_ASYNC_LOOP 1
#define MODE_SELECT_LOOP 0
#define MODE_BLOCKING 0
#define MODE_BLOCKING_RR 0

/* constants */
#define NUM_PCAPS 2
#define STATS_INTERVAL 1 /* seconds */
#define BPF_BUFSIZE (512*1024)


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* capturing interface */
const char *if_name = "ath1";

/* pcap datalink type */
static int dlt = 0;

static pcap_t *pcap_h[NUM_PCAPS];
static int pcap_fd[NUM_PCAPS];
static struct pcap_stat last_stats[NUM_PCAPS];

static struct timeval next_stats_time;
static pcap_dumper_t *dumpfile;

static int pkt_count = 0;

static int debug = 0;  /* boolean */


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void check_stats(void);

static void exec_async_loop(void);

static void exec_select_loop(void);

static void exec_blocking_loop(int roundrobin);

static void send_stats_evt(void *user);

/* callback for libpcap */
static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

/* callback for async_loop() */
static void handle_pcap_read(int fd, void *user);



/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    /* default values for command line arguments */
    const char *dlt_name = "IEEE802_11_RADIO";
    const char *dumpfilename = NULL;

    /* process command line options */
    const char *usage =
        "usage: leanclient sniffer [-gh] [-i interface] [-w file] [-y datalinktype]\n";

    int c;
    while ((c = getopt(argc, argv, ":ghi:w:y:")) != -1) {
        switch (c) {
        case 'g':
            debug = 1;
            break;
        case 'h':
            printf(usage);
            printf("\n"
                "options:\n"
                "    -g  enable debugging output\n"
                "    -h  print usage information and quit\n"
                "    -i  network interface on which to capture packets\n"
                "    -w  dump captured packets to file\n"
                "    -y  datalink type for capturing interface\n");
            exit(0);
            break;
        case 'i':
            if_name = optarg;
            break;
        case 'w':
            dumpfilename = optarg;
            break;
        case 'y':
            dlt_name = optarg;
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

    dlt = pcap_datalink_name_to_val(dlt_name);
    if (dlt < 0)
        errx(1, "invalid data link type: %s", dlt_name);

    if (dumpfilename != NULL) {
        dumpfile = pcap_dump_open(pcap_h[0], dumpfilename);
        if (dumpfile == NULL)
            errx(1, "pcap_dump_open: %s", pcap_geterr(pcap_h[0]));
    }

    int snaplen = 2048;
    char ebuf[PCAP_ERRBUF_SIZE];

    for (int i=0; i < NUM_PCAPS; i++) {
        ebuf[0] = '\0';

        pcap_h[i] = pcap_create(if_name, ebuf);
        if (pcap_h[i] == NULL)
            errx(1, "pcap_create: %s", ebuf);

        if (pcap_set_snaplen(pcap_h[i], snaplen) != 0) {
            errx(1, "pcap_set_snaplen: %s", pcap_geterr(pcap_h[i]));
            return -1;
        }

        if (pcap_set_promisc(pcap_h[i], 1) != 0) {
            errx(1, "pcap_set_promisc: %s", pcap_geterr(pcap_h[i]));
            return -1;
        }

        if (pcap_set_buffer_size(pcap_h[i], BPF_BUFSIZE) != 0)
            errx(1, "pcap_set_buffer_size: %s", pcap_geterr(pcap_h[i]));

        if (pcap_set_timeout(pcap_h[i], 0) != 0)
            errx(1, "pcap_set_timeout: %s", pcap_geterr(pcap_h[i]));

        if (pcap_activate(pcap_h[i]) != 0)
            errx(1, "pcap_activate: %s", pcap_geterr(pcap_h[i]));

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

        if (pcap_set_datalink(pcap_h[i], dlt) == -1)
            errx(1, "pcap_set_datalink: %s", pcap_geterr(pcap_h[i]));

        /*
         * not sure that this is necessary, but click's (userlevel)
         * FromDevice element does it
         */
        if (SET_PCAP_NONBLOCK) {
            printf("setting pcap_setnonblock..\n");
            if (pcap_setnonblock(pcap_h[i], 1, ebuf) < 0)
                errx(1, "pcap_setnonblock: %s", ebuf);
        } else {
            printf("NOT setting pcap_setnonblock\n");
        }

        pcap_fd[i] = pcap_get_selectable_fd(pcap_h[i]);
        if (pcap_fd[i] < 0)
            errx(1, "pcap_get_selectable_fd returned %d", pcap_fd[i]);

        /* check our BPF buffer size */
        int buf_len = -1;
        if (ioctl(pcap_fd[i], BIOCGBLEN, &buf_len) == -1)
            err(1, "ioctl(BIOCGBLEN)");

        printf("BPF buffer for pcap %d is %u bytes\n", i, buf_len);

        if (SET_BIOCIMMEDIATE) {
            printf("setting BIOCIMMEDIATE...\n");

            int rv, yes = 1;
            if ((rv = ioctl(pcap_fd[i], BIOCIMMEDIATE, &yes)) == -1)
                warn("ioctl(BIOCIMMEDIATE)");
            else if (rv != 0)
                warnx("ioctl(BIOCIMMEDIATE) returned %d", rv);
        } else {
            printf("NOT setting BIOCIMMEDIATE\n");
        }

        memset(&last_stats[i], '\0', sizeof(struct pcap_stat));
    }

    gettimeofday(&next_stats_time, NULL);
    next_stats_time.tv_sec += 2;

    if (MODE_ASYNC_LOOP) {
        exec_async_loop();
    }
    else if (MODE_SELECT_LOOP) {
        exec_select_loop();
    }
    else if (MODE_BLOCKING) {
        exec_blocking_loop(0);
    }
    else if (MODE_BLOCKING_RR) {
        exec_blocking_loop(1);
    }
    else {
        errx(1, "no mode enabled!\n");
    }

    printf("done!\n");

    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

static void
check_stats(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    if ((now.tv_sec > next_stats_time.tv_sec) ||
        ((now.tv_sec == next_stats_time.tv_sec) &&
            (now.tv_usec >= next_stats_time.tv_usec))) {

        send_stats_evt(NULL);
        next_stats_time.tv_sec += STATS_INTERVAL;
    }
}

static void
exec_async_loop(void)
{
    for (int i=0; i < NUM_PCAPS; i++) {
        int priority = 10 + i;  /* somewhat arbitrary */
        if (async_add_read_fd(pcap_fd[i], priority, async_true_check,
                handle_pcap_read, (void*)i) != 0)
            err(1, "async_add_read_fd");
    }

    /* every STATS_INTERVAL seconds, send stats to server */
    if (async_schedule_sec(STATS_INTERVAL, send_stats_evt, NULL, 1) == NULL)
        err(1, "async_schedule(send_stats_evt)");

    /* kick off the async loop */
    printf("entering async loop..\n");

    int rv = async_loop();
    if (rv == -1) {
        warn("async_loop");
    } else if (rv == -2) {
        printf("async_loop terminated by async_breakloop\n");
    } else {
        printf("async_loop terminated on its own\n");
    }
}

static void
exec_select_loop(void)
{
    fd_set zeroset;
    FD_ZERO(&zeroset);

    while (1)  {
        fd_set readset = zeroset;
        fd_set writeset = zeroset;
        int max_fd = 0;

        for (int i=0; i < NUM_PCAPS; i++) {
            FD_SET(pcap_fd[i], &readset);
            if (pcap_fd[i] > max_fd) max_fd = pcap_fd[i];
        }

        int rv = select(max_fd+1, &readset, &writeset, NULL, NULL);
        if (rv == -1) err(1, "select");
        assert(rv != 0);

        for (int i=0; i < NUM_PCAPS; i++) {
            if (FD_ISSET(pcap_fd[i], &readset))
                handle_pcap_read(pcap_fd[i], (void*)i);
        }

        check_stats();
    }
}

static void
exec_blocking_loop(int roundrobin)
{
    warnx("not implemented yet");

    int next_pcap = 0;
    while (1) {
        (void) next_pcap;
        return;

        check_stats();
    }
}

static void
send_stats_evt(void *user)
{
    /* reschedule this function to be called again after another interval */
    if (async_schedule_sec(STATS_INTERVAL, send_stats_evt, NULL, 1 /* daemon */) == NULL)
        warn("async_schedule(send_stats_evt)");

    for (int i=0; i < NUM_PCAPS; i++) {
        struct pcap_stat pstats;
        if (pcap_stats(pcap_h[i], &pstats) != 0)
            errx(1, "pcap_stats: %s", pcap_geterr(pcap_h[i]));

        u_int recv = pstats.ps_recv - last_stats[i].ps_recv;
        u_int drop = pstats.ps_drop - last_stats[i].ps_drop;

        printf("STATS[%d]:  kern-recv: %u, kern-drop: %u, drop-perc: %u%%\n",
            i, recv, drop, drop*100/recv);

        last_stats[i] = pstats;
    }
}

static void
handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    pkt_count++;
    if (dumpfile != NULL)
        pcap_dump((void*)dumpfile, h, sp);
}

/* async loop callback */
static void
handle_pcap_read(int fd, void *user)
{
    u_int start_pkt_count = pkt_count;
    int index = (int)user;

    /*
     * from pcap(3):
     *
     * A cnt of -1 processes all the packets received in one buffer when read-
     * ing  a  live  capture,  or  all  the packets in the file when reading a
     * ``savefile''.
     */
    int rv = pcap_dispatch(pcap_h[index], -1, handle_packet, user);

    if (debug && (rv != -1)) {
        printf("pcap_dispatch[%d] captured %d packets\n", index,
            pkt_count - start_pkt_count);
    }

    switch (rv) {
    case -2:  /* pcap_breakloop called */
        break;

    case -1:  /* pcap error */
        errx(1, "pcap_dispatch: %s", pcap_geterr(pcap_h[index]));
        break;

    case 0:  /* end of file reached or read timeout before any captures */
        printf("  xxxx  warning: no packets returned from pcap_dispatch  xxxx  ");
        break;

    default:  /* yay - some packets were captured */
        assert(rv > 0);
        break;
    }
}
