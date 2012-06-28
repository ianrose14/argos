/*
 * Author: Ian Rose
 * Date Created: Jul 2, 2009
 */

#include <assert.h>
#include <err.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/bpf.h>  /* must include before pcap/pcap.h */
#include <pcap/pcap.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#include "async.h"
#include "pktparse.h"
#include "pktparse-print.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

#define SET_BIOCIMMEDIATE 1
#define SNAPLEN 2048


/**********************/
/*  STATIC VARIABLES  */
/**********************/

struct pcap_extra {
    pcap_t *pcap_h;
    u_int pkt_count;
};

static struct pcap_extra *pcaps;
static int dlt = 0;
static int quit_requests = 0;
static long long int pkt_delay = 0;
static int verbose = 0;


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

/* callback for libpcap */
static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

static void handle_pcap_read(int fd, void *arg);

static void signal_handler(int signum);


/**********/
/*  MAIN  */
/**********/

int main(int argc, char **argv)
{
    /* default values for command line arguments */
    const char *if_name = "ath0";
    const char *dlt_name = "IEEE802_11_RADIO";
    const char *primary_bpf = "";
    const char *secondary_bpf = NULL;
    int npcaps = 1;
    int reverse_priority = 0;
    unsigned int duration = 0;

    /* process command line options */
    const char *usage =
        "usage: multipcap-test [-ehv] [-b bpf-expr] [-d delay] [-i interface]"
        " [-n num-pcaps] [-s bpf-expr] [-t duration] [-y datalinktype]\n";

    int c;
    while ((c = getopt(argc, argv, ":b:d:ehi:n:s:t:vy:")) != -1) {
        switch (c) {
        case 'b':
            primary_bpf = optarg;
            break;
        case 'd':
            pkt_delay = atoll(optarg);
            break;
        case 'e':
            reverse_priority = 1;
            break;
        case 'h':
            printf(usage);
            printf(
                "    -b  specify the primary BPF filter\n"
                "    -d  artificial packet processing delay (usec)\n"
                "    -e  reverse priority (make first pcap top priority"
                " instead of bottom)\n"
                "    -h  print usage information and quit\n"
                "    -i  network interface on which to capture packets\n"
                "    -n  number of pcap descriptors to open\n"
                "    -s  specify a secondary BPF filter\n"
                "    -t  quit after specified time (sec)\n"
                "    -v  be verbose\n"
                "    -y  datalink type for capturing interface\n"
                "\n"
                " If no secondary BPF filter is specified, the primary BPF filter\n"
                " (if any) is applied to all pcap descriptors.  Otherwise, the\n"
                " primary BPF filter (if any) is applied only to the first\n"
                " descriptor and the secondary BPF filter is applied to all\n"
                " others.\n");
            exit(0);
            break;
        case 'i':
            if_name = optarg;
            break;
        case 'n':
            npcaps = atoi(optarg);
            break;
        case 's':
            secondary_bpf = optarg;
            break;
        case 't':
            duration = atoi(optarg);
            break;
        case 'v':
            verbose = 1;
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

    /* set up signal handlers */
    if (signal(SIGALRM, SIG_IGN) != SIG_IGN)
        signal(SIGALRM, signal_handler);

    if (signal(SIGINT, SIG_IGN) != SIG_IGN)
        signal(SIGINT, signal_handler);

    if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
        signal(SIGTERM, signal_handler);

    pcaps = (struct pcap_extra*)malloc(sizeof(struct pcap_extra)*npcaps);
    if (pcaps == NULL) err(1, "malloc");

    const char **bpfs = (const char **)malloc(sizeof(char*)*npcaps);
    if (bpfs == NULL) err(1, "malloc");

    dlt = pcap_datalink_name_to_val(dlt_name);
    if (dlt < 0)
        errx(1, "invalid data link type: %s", dlt_name);

    char ebuf[PCAP_ERRBUF_SIZE];
    ebuf[0] = '\0';

    bpf_u_int32 netnum = 0, netmask = 0;
    if (pcap_lookupnet(if_name, &netnum, &netmask, ebuf) == -1)
        errx(1, "pcap_lookupnet: %s", ebuf);

    for (int i=0; i < npcaps; i++) {
        pcaps[i].pcap_h = pcap_open_live(if_name, SNAPLEN, 1 /* promisc */,
            0 /* timeout */, ebuf);
        if (pcaps[i].pcap_h == NULL)
            errx(1, "pcap_open_live: %s", ebuf);
        else if (*ebuf) {
            warnx("pcap_open_live [warn]: %s", ebuf);
            ebuf[0] = '\0';
        }
        pcaps[i].pkt_count = 0;

        if (pcap_set_datalink(pcaps[i].pcap_h, dlt) == -1)
            errx(1, "pcap_set_datalink: %s", pcap_geterr(pcaps[i].pcap_h));

        if (i == 0)
            bpfs[i] = (strcmp(primary_bpf, "") == 0) ? NULL : primary_bpf;
        else
            bpfs[i] = (secondary_bpf == NULL) ? bpfs[0] : secondary_bpf;
        
        struct bpf_program bpf;
        if (bpfs[i] != NULL) {
            if (pcap_compile(pcaps[i].pcap_h, &bpf, bpfs[i], 1 /* optimize */,
                    netmask) == -1)
                errx(1, "pcap_compile: %s", pcap_geterr(pcaps[i].pcap_h));
            if (pcap_setfilter(pcaps[i].pcap_h, &bpf) == -1)
                errx(1, "pcap_setfilter: %s", pcap_geterr(pcaps[i].pcap_h));
        }

        int fd = pcap_get_selectable_fd(pcaps[i].pcap_h);

        if (SET_BIOCIMMEDIATE) {
            int r, yes = 1;
            if ((r = ioctl(fd, BIOCIMMEDIATE, &yes)) == -1)
                err(1, "%s: BIOCIMMEDIATE", if_name);
            else if (r != 0)
                warnx("%s: BIOCIMMEDIATE returns %d", if_name, r);
        }

        /*
         * not 100% sure this is necessary, but click's userlevel FromDevice
         * element does it so maybe so...
         */
        if (pcap_setnonblock(pcaps[i].pcap_h, 1, ebuf) < 0)
            errx(1, "pcap_setnonblock: %s", ebuf);

        int priority = reverse_priority ? i + 5 : npcaps - i + 4;
        if (async_add_read_fd(fd, priority, async_true_check, handle_pcap_read,
                &pcaps[i]) == -1)
            err(1, "async_add_read_fd");
        printf("added fd %d (bpf=%s) to async loop w/ prio %d\n",
            fd, bpfs[i], priority);
    }

    if (duration > 0) alarm(duration);

    int rv = async_loop();
    if (rv == -1)
        err(1, "async_loop");
    else if (rv == -2)
        printf("async_loop terminated by async_breakloop\n");
    else
        printf("async_loop terminated on its own\n");

    for (int i=0; i < npcaps; i++) {
        int fd = pcap_get_selectable_fd(pcaps[i].pcap_h);
        struct pcap_stat ps;
        if (pcap_stats(pcaps[i].pcap_h, &ps) != 0)
            errx(1, "pcap_stats: %s", pcap_geterr(pcaps[i].pcap_h));
        printf("%d: capt=%d, recv=%d, drop=%d  (bpf=%s)\n", fd,
            pcaps[i].pkt_count, ps.ps_recv, ps.ps_drop, bpfs[i]);
        pcap_close(pcaps[i].pcap_h);
    }

    printf("\n");

    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == -1)
        err(1, "getrusage");

    fprintf(stderr, " sys time: %d.%06lus\n", ru.ru_stime.tv_sec, ru.ru_stime.tv_usec);
    fprintf(stderr, "user time: %d.%06lus\n", ru.ru_utime.tv_sec, ru.ru_utime.tv_usec);

    return 0;
}

/* called by pcap_dispatch */
static void
handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    struct pcap_extra *pe = (struct pcap_extra*)user;
    pe->pkt_count++;
    if (quit_requests > 0)
        pcap_breakloop(pe->pcap_h);

    /*
    struct packet pkt;
    if (pktparse_parse(h, sp, dlt, &pkt, 0) == -1) {
        warnx("pktparse_parse: %s", pkt.errmsg);
    } else {
        if (pkt.tcp_hdr != NULL) {
            char buf[256];
            if (pktparse_print_full_v(buf, sizeof(buf), &pkt) == -1) {
                warnx("pktparse_print_full");
            } else {
                printf("%d captured: %s\n", pcap_fileno(pe->pcap_h), buf);
            }
        }
    }
    */

    if (pkt_delay > 0)
        usleep(pkt_delay);
}

/* async loop callback */
static void
handle_pcap_read(int fd, void *arg)
{
    struct pcap_extra *pe = (struct pcap_extra*)arg;
    u_int start_total_recv = pe->pkt_count;

    assert(fd == pcap_get_selectable_fd(pe->pcap_h));

    /*
     * from pcap(3):
     *
     * A cnt of -1 processes all the packets received in one buffer when read-
     * ing  a  live  capture,  or  all  the packets in the file when reading a
     * ``savefile''.
     */
    int cnt = 10;
    int rv = pcap_dispatch(pe->pcap_h, cnt, handle_packet, (u_char*)pe);

    if ((rv != -1) && verbose)
        printf("pcap_dispatch on fd %d captured %d packets\n", fd,
            pe->pkt_count - start_total_recv);

    switch (rv) {
    case -2:  /* pcap_breakloop called */
        break;

    case -1:  /* pcap error */
        errx(1, "pcap_dispatch (fd=%d): %s", fd, pcap_geterr(pe->pcap_h));
        break;

    case 0:  /* end of file reached or no packets received */
        warnx("pcap_dispatch (fd=%d) returned 0", fd);
        break;

    default:  /* yay - some packets were captured */
        assert(rv > 0);
        break;
    }

    /* check if pcap_dispatch was interrupted due to a quit request */
    if (quit_requests > 0)
        async_breakloop();
}

static void
signal_handler(int signum)
{
    if ((signum == SIGALRM) || (signum == SIGINT) || (signum == SIGTERM)) {
        quit_requests++;
        async_breakloop();

        if (quit_requests > 1) {
            /* there have been multiple "quit" signals; force exit */
            fprintf(stderr, "force quit from signal %d\n", signum);
            fflush(stderr);
            exit(1);
        }
    } else {
        /* bad signal received */
        assert(0  /* invalid signal */);
    }
}
