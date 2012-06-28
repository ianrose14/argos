/*
 * Author: Ian Rose
 * Date Created: Sep 30, 2009
 *
 * Simulation of in-network merging, map-reduce style.
 *
 * This program makes a few major simplifications (errors).  First, it assumes
 * that all frames are unique, such that the merging process produces NO data
 * reduction.  However, you can (coarsely) compensate for this by decreasing the
 * reduction factor.  Second, it completely ignores all control frames (because
 * these are annoying to attribute to an AP).  Third, it completely ignores all
 * citysense traffic.  Fourth, it maps each BSS entirely to one node, which is
 * fine for infrastructure networks (where usually 1 BSSID <--> 1 AP), but sucks
 * for large adhoc networks where many APs share the same BSSID.
 */

/*
 * Differences from src/click/elements/WifiOverlay:
 * - broadcast frames not passed up to local node
 * - control frames ignored
 * - citysense-exp/-mgmt/-golden frames ignored
 */

/* system includes */
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pktparse.h>
#include <pktparse-print.h>

/* local includes */
#include "uthash.h"


/*****************/
/*  DEFINITIONS  */
/*****************/

#define SNIFFER_ARR_SIZE 300


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct accesspoint {
    UT_hash_handle hh;  /* uthash handle (required for hashing) */
    u_char bssid[6];  /* AP's actual mac address, NOT the bssid */
    uint64_t num_tods_pkts;
    uint64_t num_fromds_pkts;
    uint64_t num_bytes;  /* includes both fromds and tods */
    int home_node;  /* a sniffer ID */
};

struct sniffer {
    u_char is_wired;
    struct sniffer *parent;

    /* total traffic captured by this sniffer from each AP */
    struct accesspoint *captured_traffic;
    uint64_t total_captured;

    /* traffic breakdown */
    uint64_t influx_traffic;
    uint64_t outflux_traffic;
    uint64_t origin_traffic;
};


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

static int get_home_node(u_char *bssid);

static int get_next_hop(int from, int to);

static void initialize_sniffers(void);

static int parse_sniffer_id(const char *filename);


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* array of sniffers, indexed by node ID (not all entries are valid!) */
static struct sniffer *sniffers[SNIFFER_ARR_SIZE];

/* hash of all of the APs heard by all of the sniffers in aggregate */
static struct accesspoint *ap_hash = NULL;

static int dlt = -1;

/* used only for error-checking */
static uint64_t total_pkts = 0;
static uint64_t total_tods_pkts = 0;
static uint64_t total_fromds_pkts = 0;

/* coarse timing */
static time_t first_pkt = 0, last_pkt = 0;


/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    double reduction_factor = 1.0;
    int debug = 0;

    int c;
    while ((c = getopt(argc, argv, ":ghr:")) != -1) {
        switch (c) {
        case 'g':
            debug = 1;
            break;
        case 'h':
            printf("mapreduce-sim [-gh] [-r reduction]\n");
            exit(0);
            break;
        case 'r':
            reduction_factor = atof(optarg);
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
    argc -= optind;
    argv += optind;

    initialize_sniffers();

    uint64_t total_from_sniffers = 0;

    /* phase 1: read all files */
    for (int i=0; i < argc; i++) {
        if (debug) printf("processing file %s...\n", argv[i]);
        int sniffer_id = parse_sniffer_id(argv[i]);

        struct sniffer *sniffer = sniffers[sniffer_id];
        if (sniffer == NULL) {
            printf("warning: no sniffer data available for %03d (skipping)\n", sniffer_id);
            continue;
        }

        char ebuf[PCAP_ERRBUF_SIZE];
        *ebuf = '\0';

        pcap_t *pcap_h = pcap_open_offline(argv[i], ebuf);
        if (pcap_h == NULL)
            errx(1, "pcap_open_offline: %s", ebuf);
        else if (*ebuf)
            printf("warning: pcap_open_offline: %s\n", ebuf);

        dlt = pcap_datalink(pcap_h);

        int rv = pcap_loop(pcap_h, -1, handle_packet, (void*)sniffer);
        if (rv == -1)
            errx(1, "pcap_dispatch: %s", pcap_geterr(pcap_h));

        struct accesspoint *ap;
        int ap_count = 0;
        uint64_t pkt_count = 0;
        for (ap = sniffer->captured_traffic; ap != NULL; ap = ap->hh.next) {
            ap_count++;
            pkt_count += ap->num_tods_pkts + ap->num_fromds_pkts;
        }

        total_from_sniffers += ap_count;

        if (debug)
            printf("citysense%03d: captured %llu packets from %d APs\n",
                sniffer_id, pkt_count, ap_count);
    }

    /* phase 1 complete - do some sanity checks */

    /* total captured packets must equal total AP packets */

    struct accesspoint *ap;
    int ap_count = 0;
    uint64_t pkt_count = 0;
    uint64_t tods_pkt_count = 0;
    uint64_t fromds_pkt_count = 0;
    for (ap = ap_hash; ap != NULL; ap = ap->hh.next) {
        ap_count++;
        pkt_count += ap->num_tods_pkts + ap->num_fromds_pkts;
        tods_pkt_count += ap->num_tods_pkts;
        fromds_pkt_count += ap->num_fromds_pkts;
    }

    assert(total_pkts == pkt_count);
    assert(total_tods_pkts == tods_pkt_count);
    assert(total_fromds_pkts == fromds_pkt_count);

    if (debug) {
        printf("start = %s", ctime(&first_pkt));
        printf("end   = %s", ctime(&last_pkt));
        printf("total: captured %llu packets from %d APs\n", pkt_count, ap_count);
    }

    /* phase 2: figure out a home-node for each AP */
    for (ap = ap_hash; ap != NULL; ap = ap->hh.next) {
        int best_fromds_sniffer = -1;
        int best_tods_sniffer = -1;
        int most_fromds_captures = 0;
        int most_tods_captures = 0;

        for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
            if (sniffers[i] == NULL) continue;

            struct sniffer *sniffer = sniffers[i];
            struct accesspoint *ap_elt = NULL;
            HASH_FIND(hh, sniffer->captured_traffic, ap->bssid, 6, ap_elt);
            if (ap_elt == NULL) continue;

            if (ap_elt->num_fromds_pkts > most_fromds_captures) {
                most_fromds_captures = ap_elt->num_fromds_pkts;
                best_fromds_sniffer = i;
            }

            if (ap_elt->num_tods_pkts > most_tods_captures) {
                most_tods_captures = ap_elt->num_tods_pkts;
                best_tods_sniffer = i;
            }
        }

        assert((best_fromds_sniffer > -1) || (best_tods_sniffer > -1));
        assert(most_fromds_captures + most_tods_captures > 0);

        /* give preference to the best fromds sniffer */
        if (best_fromds_sniffer != -1)
            ap->home_node = best_fromds_sniffer;
        else
            ap->home_node = best_tods_sniffer;
    }

    /* total traffic flowing over each link */
    uint64_t rawstream_linkloads[SNIFFER_ARR_SIZE][SNIFFER_ARR_SIZE];
    uint64_t mapreduce_linkloads[SNIFFER_ARR_SIZE][SNIFFER_ARR_SIZE]; 

    bzero(rawstream_linkloads, sizeof(uint64_t)*SNIFFER_ARR_SIZE*SNIFFER_ARR_SIZE);
    bzero(mapreduce_linkloads, sizeof(uint64_t)*SNIFFER_ARR_SIZE*SNIFFER_ARR_SIZE);

    /* phase 3: route captured traffic to where it needs to go */
    for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
        struct sniffer *sniffer = sniffers[i];
        if (sniffer == NULL) continue;

        struct accesspoint *ap;
        for (ap = sniffer->captured_traffic; ap != NULL; ap = ap->hh.next) {
            int home_node = get_home_node(ap->bssid);
            if (home_node == i) {
                /* this sniffer is the home node for this AP */
                sniffer->origin_traffic += ap->num_bytes;
            } else {
                /* this sniffer needs to ship this AP's traffic elsewhere */
                int src = i;
                int hopcount = 0;
                do {
                    /* to catch bugs: */
                    hopcount++;
                    if (hopcount >= 255) {
                        fprintf(stderr, "routing loop.  src=%d, dst=%d\n", i, home_node);
                        abort();
                    }

                    int dst = get_next_hop(src, home_node);
                    struct sniffer *router = sniffers[dst];
                    assert(router != NULL);

                    /*
                     * be careful about ordering because we want to count all
                     * traffic on a link (going both directions) as one sum
                     */
                    if (src > dst)
                        mapreduce_linkloads[dst][src] += ap->num_bytes;
                    else
                        mapreduce_linkloads[src][dst] += ap->num_bytes;

                    src = dst;
                } while (src != home_node);

                sniffers[home_node]->influx_traffic += ap->num_bytes;
                sniffer->outflux_traffic += ap->num_bytes;
            }
        }
    }

    /* phase 4: calculate traffic load when sending back to wired sink */
    for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
        struct sniffer *sniffer = sniffers[i];
        if (sniffer == NULL) continue;

        /*
         * for the map-reduce case, calculate a path from this sniffer to the
         * nearest sink, adding this sniffer's influx traffic load + its origin
         * traffic load (multiplied by the reduction factor) to each link we
         * traverse
         */
        uint64_t pre_traffic = sniffer->influx_traffic + sniffer->origin_traffic;
        uint64_t mapreduce_traffic = (uint64_t)(pre_traffic*reduction_factor);

        /*
         * for the raw-streaming case, calculate a path from this sniffer to the
         * nearest sink, adding the total captured traffic to every link we
         * traverse
         */
        uint64_t rawstream_traffic = sniffer->total_captured;

        int src = i;
        int hopcount = 0;
        while (1) {
            struct sniffer *router = sniffers[src];
            assert(router != NULL);
            if (router->is_wired) break;  /* done! */

            /* to catch bugs: */
            hopcount++;
            if (hopcount >= 255) {
                fprintf(stderr, "routing loop.  src=%d, dst=-1 (wired sink)\n", i);
                abort();
            }

            int dst = get_next_hop(src, -1 /* -1 = wired sink */);

            /*
             * be careful about ordering because we want to count all traffic on
             * a link (going both directions) as one sum 
             */
            if (src > dst) {
                mapreduce_linkloads[dst][src] += mapreduce_traffic;
                rawstream_linkloads[dst][src] += rawstream_traffic;
            } else {
                mapreduce_linkloads[src][dst] += mapreduce_traffic;
                rawstream_linkloads[src][dst] += rawstream_traffic;
            }

            src = dst;
        }
    }

#define bytes2kbps(val) \
    (8*(((double)val)/1024)/(last_pkt - first_pkt))

    /* phase 4 complete - do some sanity checks */
    uint64_t sum_influx = 0, sum_outflux = 0, sum_origin = 0, sum_capture = 0;

    for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
        if (sniffers[i] == NULL) continue;
        struct sniffer *sniffer = sniffers[i];

        sum_influx += sniffer->influx_traffic;
        sum_outflux += sniffer->outflux_traffic;
        sum_origin += sniffer->origin_traffic;
        sum_capture += sniffer->total_captured;

        if (debug) {
            printf("sniffer %03d capture=%.1f Kb/s influx=%.1f Kb/s"
                " outflux=%.1f Kb/s origin=%.1f Kb/s\n",
                i, bytes2kbps(sniffer->total_captured),
                bytes2kbps(sniffer->influx_traffic),
                bytes2kbps(sniffer->outflux_traffic),
                bytes2kbps(sniffer->origin_traffic));
        }
    }

    if (debug) {
        printf("sum(total_influx_rates) = %llu\n", sum_influx);
        printf("sum(total_outflux_rates) = %llu\n", sum_outflux);
        printf("sum(total_origin_rates) = %llu\n", sum_origin);
        printf("outflux + origin total = %llu\n", sum_outflux + sum_origin);
        printf("sum(total_capture_loads) = %llu\n", sum_capture);
    }

    assert((sum_outflux + sum_origin) == sum_capture);
    assert(sum_influx == sum_outflux);

    /* calculate the loads on the wired sinks */
    uint64_t rawstream_sink_loads[SNIFFER_ARR_SIZE];
    bzero(rawstream_sink_loads, sizeof(uint64_t)*SNIFFER_ARR_SIZE);

    uint64_t mapreduce_sink_loads[SNIFFER_ARR_SIZE];
    bzero(mapreduce_sink_loads, sizeof(uint64_t)*SNIFFER_ARR_SIZE);

    for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
        for (int j=0; j < SNIFFER_ARR_SIZE; j++) {
            if (sniffers[i] != NULL) {
                if (sniffers[i]->is_wired) {
                    rawstream_sink_loads[i] += rawstream_linkloads[i][j];
                    mapreduce_sink_loads[i] += mapreduce_linkloads[i][j];
                }
            }
            if (sniffers[j] != NULL) {
                if (sniffers[j]->is_wired) {
                    rawstream_sink_loads[j] += rawstream_linkloads[i][j];
                    mapreduce_sink_loads[j] += mapreduce_linkloads[i][j];
                }
            }
        }
    }

    if (debug) {
        printf("\n"
            "---- RawStream Traffic ----\n");
        for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
            for (int j=0; j < SNIFFER_ARR_SIZE; j++) {
                if (rawstream_linkloads[i][j] != 0) {
                    printf("link [%03d <-> %03d]: %.1f Kb/s\n",
                        i, j, bytes2kbps(rawstream_linkloads[i][j]));
                }
            }
        }
    }

    printf("\n"
        "---- RawStream Sink Loads ----\n");

    for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
        if (rawstream_sink_loads[i] != 0)
            printf("sink %03d: %.1f Kb/s\n",
                i, bytes2kbps(rawstream_sink_loads[i]));
    }

    if (debug) {
        printf("\n"
            " ---- MapReduce Traffic ----\n");
        for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
            for (int j=0; j < SNIFFER_ARR_SIZE; j++) {
                if (mapreduce_linkloads[i][j] != 0) {
                    printf("link [%03d <-> %03d]: %.1f Kb/s\n",
                        i, j, bytes2kbps(mapreduce_linkloads[i][j]));
                }
            }
        }
    }

    printf("\n"
        "---- MapReduce Sink Loads ----\n");

    for (int i=0; i < SNIFFER_ARR_SIZE; i++) {
        if (mapreduce_sink_loads[i] != 0)
            printf("sink %03d: %.1f Kb/s\n",
                i, bytes2kbps(mapreduce_sink_loads[i]));
    }

    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

static
void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp)
{
    if ((first_pkt == 0) || (h->ts.tv_sec < first_pkt)) first_pkt = h->ts.tv_sec;
    if (h->ts.tv_sec > last_pkt) last_pkt = h->ts.tv_sec;

    struct packet pkt;
    int flags = PKTPARSE_IGNORE_BADLLC;
    if (pktparse_parse(h, sp, dlt, &pkt, flags) == -1) {
        printf("warning: error parsing packet: %s\n", pkt.errmsg);
        return;
    }

    if (pkt.wifi_hdr == NULL) {
        printf("warning: packet received with no wifi header\n");
        return;
    }

    /*
     * We assume that all FromDS frames, and all Beacons and ProbeResp frames
     * are from APs; all other frames we assume are from stations.
     */
    int from_ap = 0;

    if (FC_TYPE(pkt.wifi_fc) == T_MGMT) {
        if ((FC_SUBTYPE(pkt.wifi_fc) == ST_BEACON) ||
            (FC_SUBTYPE(pkt.wifi_fc) == ST_PROBE_RESPONSE))
            from_ap = 1;
    }

    if (FC_FROM_DS(pkt.wifi_fc) && (FC_TO_DS(pkt.wifi_fc) == 0))
        from_ap = 1;

    const u_char *bssid = NULL;
    if (pktparse_extract_wifi_addrs(pkt.wifi_hdr, NULL, NULL, NULL, NULL, &bssid) != 0) {
        fprintf(stderr, "pktparse_extract_wifi_addrs: %s\n", strerror(errno));
        abort();
    }

    /* this is a control frame - ignore it */
    if (bssid == NULL) return;

    static u_char citysense_bssid_prefix[5] = { 0x12, 0, 0, 0, 0 };
    if (memcmp(citysense_bssid_prefix, bssid, sizeof(citysense_bssid_prefix)) == 0) {
        /* this is a citysense frame - ignore it */
        return;
    }

    total_pkts++;
    if (from_ap)
        total_fromds_pkts++;
    else
        total_tods_pkts++;

    struct accesspoint *ap_elt = NULL;
    HASH_FIND(hh, ap_hash, bssid, 6, ap_elt);
    if (ap_elt == NULL) {
        ap_elt = (struct accesspoint*)malloc(sizeof(struct accesspoint));
        if (ap_elt == NULL)
            err(1, "malloc");
        bzero(ap_elt, sizeof(struct accesspoint));
        memcpy(&ap_elt->bssid, bssid, 6);
        HASH_ADD(hh, ap_hash, bssid, 6, ap_elt);
    }

    /*
     * note: this COMPLETELY IGNORES merging - it assumes that all packets are
     * unique
     */
    if (from_ap)
        ap_elt->num_fromds_pkts++;
    else
        ap_elt->num_tods_pkts++;

    ap_elt->num_bytes += h->caplen;

    struct sniffer *sniffer = (struct sniffer*)user;
    assert(sniffer != NULL);
    sniffer->total_captured += h->caplen;

    /* now update the sniffer's captured-traffic hash */
    ap_elt = NULL;
    HASH_FIND(hh, sniffer->captured_traffic, bssid, 6, ap_elt);
    if (ap_elt == NULL) {
        ap_elt = (struct accesspoint*)malloc(sizeof(struct accesspoint));
        if (ap_elt == NULL)
            err(1, "malloc");
        bzero(ap_elt, sizeof(struct accesspoint));
        memcpy(&ap_elt->bssid, bssid, 6);
        HASH_ADD(hh, sniffer->captured_traffic, bssid, 6, ap_elt);
    }

    if (from_ap)
        ap_elt->num_fromds_pkts++;
    else
        ap_elt->num_tods_pkts++;

    ap_elt->num_bytes += h->caplen;
}

static
int get_home_node(u_char *bssid)
{
    struct accesspoint *ap_elt = NULL;
    HASH_FIND(hh, ap_hash, bssid, 6, ap_elt);
    if (ap_elt == NULL) {
        fprintf(stderr, "get_home_node() called for nonexistant AP: %02X:%02X:%02X:%02X:%02X:%02X\n",
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        abort();
    }
    return ap_elt->home_node;
}

static int
get_next_hop(int from, int to)
{
    switch (from) {
    case 1:
        if (to == 2) return 2;
        if (to == 3) return 7;
        if (to == 4) return 4;
        if (to == 6) return 6;
        if (to == 7) return 7;
        if (to == 10) return 10;
        if (to == 11) return 7;
        if (to == 12) return 6;
        break;

    case 2:
        if (to == 1) return 1;
        if (to == 3) return 7;
        if (to == 4) return 4;
        if (to == 6) return 6;
        if (to == 7) return 7;
        if (to == 10) return 10;
        if (to == 11) return 7;
        if (to == 12) return 4;  /* 006 is used almost as often */
        break;

    case 3:
        if (to == -1) return 7;  /* to wired sink */
        if (to == 1) return 7;
        if (to == 2) return 7;
        if (to == 4) return 12;
        if (to == 6) return 6;
        if (to == 7) return 7;
        if (to == 10) return 7;
        if (to == 11) return 11;
        if (to == 12) return 12;
        break;

    case 4:
        if (to == -1) return 7;  /* to wired sink */
        if (to == 1) return 1;
        if (to == 2) return 2;
        if (to == 3) return 12;
        if (to == 6) return 6;
        if (to == 7) return 7;
        if (to == 10) return 10;
        if (to == 11) return 7;  /* 12 is used almost as often */
        if (to == 12) return 12;
        break;

    case 6:
        if (to == -1) return 1;  /* to wired sink */
        if (to == 1) return 1;
        if (to == 2) return 2;
        if (to == 3) return 3;
        if (to == 4) return 4;
        if (to == 7) return 7;
        if (to == 10) return 10;
        if (to == 11) return 7;  /* 3 is used almost as often */
        if (to == 12) return 12;
        break;

    case 7:
        if (to == -1) return 1;  /* to wired sink */
        if (to == 1) return 1;
        if (to == 2) return 2;
        if (to == 3) return 3;
        if (to == 4) return 4;
        if (to == 6) return 6;
        if (to == 10) return 10;
        if (to == 11) return 3;
        if (to == 12) return 12;
        break;

    case 10:
        if (to == -1) return 2;  /* to wired sink */
        if (to == 1) return 1;
        if (to == 2) return 2;
        if (to == 3) return 7;
        if (to == 4) return 4;
        if (to == 6) return 6;
        if (to == 7) return 7;
        if (to == 11) return 7;
        if (to == 12) return 12;
        break;

    case 11:
        if (to == -1) return 3;  /* to wired sink */
        if (to == 1) return 3;
        if (to == 2) return 3;
        if (to == 3) return 3;
        if (to == 4) return 3;
        if (to == 6) return 3;
        if (to == 7) return 3;
        if (to == 10) return 3;
        if (to == 12) return 3;
        break;

    case 12:
        if (to == -1) return 6;  /* to wired sink; 4 is used almost as often */
        if (to == 1) return 6;
        if (to == 2) return 6;  /* 4 is used almost as often */
        if (to == 3) return 3;
        if (to == 4) return 4;
        if (to == 6) return 6;
        if (to == 7) return 7;
        if (to == 10) return 10;
        if (to == 11) return 3;
        break;

    default:
        break;
    }

    fprintf(stderr, "no route from %03d to %03d\n", from, to);
    abort();
}

static
void initialize_sniffers(void)
{
    /* create sniffers */
    bzero(sniffers, SNIFFER_ARR_SIZE*sizeof(struct sniffer*));

    /* citysense001 */
    sniffers[1] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[1]->captured_traffic = NULL;
    sniffers[1]->is_wired = 1;

    /* citysense002 */
    sniffers[2] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[2]->captured_traffic = NULL;
    sniffers[2]->is_wired = 1;

    /* citysense003 */
    sniffers[3] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[3]->captured_traffic = NULL;
    /* citysense003 is wired but uses the mesh due to its IP config */

    /* citysense004 */
    sniffers[4] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[4]->captured_traffic = NULL;

    /* citysense006 */
    sniffers[6] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[6]->captured_traffic = NULL;

    /* citysense007 */
    sniffers[7] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[7]->captured_traffic = NULL;

    /* citysense010 */
    sniffers[10] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[10]->captured_traffic = NULL;

    /* citysense011 */
    sniffers[11] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[11]->captured_traffic = NULL;

    /* citysense012 */
    sniffers[12] = (struct sniffer*)malloc(sizeof(struct sniffer));
    sniffers[12]->captured_traffic = NULL;
}

static
int parse_sniffer_id(const char *filename)
{
    const char *base = basename(filename);
    if (base == NULL) goto fail;

    char cbuf[128];
    snprintf(cbuf, sizeof(cbuf), base);
    char *period = strchr(cbuf, '.');
    if (period == NULL) goto fail;
    period[0] = '\0';
    const char *start = cbuf;
    while ((start[0] != '\0') && (!isdigit(start[0])))
        start++;

    if (start[0] == '\0') goto fail;
    return atoi(start);

 fail:
    printf("warning: failed to parse node num from %s, returning 0\n", filename);
    return 0;
}
