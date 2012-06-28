/*
 * Author: Ian Rose
 * Date Created: Feb 14, 2010
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <string.h>
#include <pktparse.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "orion/time.h"
#include "uthash.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

/*
 * this value was chosen because its the default session timeout for ASPs; other
 * common values are 10, 30 and 60 minutes.
 */
#define WEBREQ_SESSION_MAXDUR (20*60)  /* 20 minutes */


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct mapped_string {
    UT_hash_handle hh;  /* uthash handle (required for hashing) */
    char src[256];      /* key */
    char dst[256];
};

/*
 * whenever two web requests from the same source IP to the same host take
 * place within some time limit, they are counted as the same "session"
 */
struct web_session_id {
    struct in_addr src_ip;
    char host[512];  /* guessed at max length */
} __attribute__((__packed__));

struct web_session {
    UT_hash_handle hh;  /* uthash handle (required for hashing) */
    struct web_session_id *keyptr;
    struct timeval session_timeout;
};


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* datalink type */
static int dlt;

/* suppress parsing errors? */
static u_char quiet = 0;

/* print debugging info? */
static u_char debug = 0;

/* hashmap of web sessions */
static struct web_session *sessions = NULL;


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp);

static const char *remap_host(const char *host);


/**********/
/*  MAIN  */
/**********/

int main(int argc, char **argv)
{
    /* default values for command line arguments (see also static variables) */
    const char *pcap_filename = "-";
    int num_pkts = -1;

    /* process command line options */
    const char *usage = "usage: print-web-requests [options]\n";

    int c;
    while ((c = getopt(argc, argv, ":c:ghqr:")) != -1) {
        switch (c) {
        case 'c':
            num_pkts = atoi(optarg);
            break;
        case 'g':
            debug = 1;
            break;
        case 'h':
            printf(usage);
            printf(
                "    -c  process only first N packets\n"
                "    -g  print debugging info\n"
                "    -h  print usage information and quit\n"
                "    -q  suppress printing of packet-parsing errors\n"
                "    -r  read from specified file instead of stdin\n");
            exit(0);
            break;
        case 'q':
            quiet = 1;
            break;
        case 'r':
            pcap_filename = optarg;
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

    if (argc > 0)
        fprintf(stderr, "ignoring %d excess arguments\n", argc);

    /* create pcap handle (either from file or from live capture) */
    char ebuf[PCAP_ERRBUF_SIZE];
    *ebuf = '\0';

    /* "capture" from file */
    pcap_t *pcap_h = pcap_open_offline(pcap_filename, ebuf);
    if (pcap_h == NULL)
        errx(1, "pcap_open_offline: %s", ebuf);
    else if (*ebuf)
        warnx("pcap_open_offline: %s", ebuf);

    /* read dlt from file */
    dlt = pcap_datalink(pcap_h);
    
    /* start reading packets */
    if (pcap_loop(pcap_h, num_pkts, handle_packet, NULL) == -1)
        errx(1, "pcap_loop: %s", pcap_geterr(pcap_h));

    pcap_close(pcap_h);
    return 0;
}


/********************/
/*  STATIC METHODS  */
/********************/

#define PRINT_REJECTED_PACKET(h, req, ip, desc)                          \
    printf("%d.%06ld  [%s]  (ip=%s host=%s request=%s)\n",              \
        h->ts.tv_sec, h->ts.tv_usec, desc, inet_ntoa(ip),               \
        req->host ? req->host : "", req->resource)                      \

#define PRINT_SESSION_PACKET(h, req, ip, name, isnew)                    \
    if (isnew) {                                                        \
        printf("%d.%06ld  %s [new session]  (ip=%s host=%s request=%s)\n", \
            h->ts.tv_sec, h->ts.tv_usec, name, inet_ntoa(ip),           \
            req->host ? req->host : "", req->resource);                 \
    } else {                                                            \
        printf("%d.%06ld  %s [existing session]  (ip=%s host=%s request=%s)\n", \
            h->ts.tv_sec, h->ts.tv_usec, name, inet_ntoa(ip),           \
            req->host ? req->host : "", req->resource);                 \
    }                                                                   \


/* called by pcap_loop */
static void handle_packet(u_char *user, const struct pcap_pkthdr *h,
    const u_char *sp)
{
    int flags = 0;
    struct packet pkt;
    if (pktparse_parse(h, sp, dlt, &pkt, flags) == -1) {
        if (!quiet)
            fprintf(stderr, "bad packet: %s\n", pkt.errmsg);
        return;
    }

    if (pkt.ip_hdr == NULL) return;
    if (pkt.tcp_hdr == NULL) return;

    struct http_request *req = pktparse_parse_http_request((char*)pkt.unparsed,
        pkt.unparsed_len);
    if (req == NULL) return;

    struct web_session_id *key = NULL;
    size_t host_len;
    const char *host;

    if (strncmp(req->resource, "http://", 7) == 0) {
        host = req->resource + 7;
        char *slash = strchr(host, '/');
        if (slash == NULL)
            host_len = strlen(host);
        else
            host_len = slash - host;
    }
    // todo - remove this check?
    else if (req->resource[0] != '/') {
        fprintf(stderr, "warning: resource does not start with slash.  host=|%s|  resource=|%s|  version=|%s|\n",
            req->host, req->resource, req->version);
        host = req->host;
        host_len = strlen(host);
    }
    else {
        host = req->host;
        host_len = strlen(host);
    }

    key = malloc(sizeof(struct web_session_id));
    if (key == NULL)
        err(1, "malloc(%d)", sizeof(struct web_session_id));
    key->src_ip = pkt.ip_hdr->ip_src;
    strlcpy(key->host, host, sizeof(key->host));

    /*
     * If the host ends with a port number, check that its a "reasonable" HTTP
     * port; this list is copied from Wireshark's default list of HTTP ports,
     * minus 3132 (Microsoft Business Rule Engine Update Service), 11371
     * (OpenPGP key server), 3689 (Digital Audio Access Protocol) and 1900
     * (Simple Service Discovery Protocol)
     */
    char *colon = strchr(key->host, ':');
    if (colon != NULL) {
        int port = atoi(colon + 1);
        if ((port != 80) && (port != 3128) && (port != 8080) && (port != 8088)) {
            /* bad port number - assume this is not a web request */
            if (debug)
                PRINT_REJECTED_PACKET(h, req, key->src_ip, "invalid port");
            free(key);
            return;
        }

        colon[0] = '\0';
    }

    /*
     * Now strip off all but the last three "labels" (the parts of a domain name
     * separated by dots); e.g. foo.bar.cnn.com becomes just foo.cnn.com.  For
     * most domains we will (later) continue to strip the third label, giving
     * just cnn.com as the host.  The idea here is that different domains that
     * compare equally on their last two labels are probably part of the same
     * website (e.g. a web request to images.cnn.com followed by a request to
     * www.cnn.com from the same IP probably both represent the same web
     * session).
     *
     * Some sites are hard-coded to be exceptions; these sites each host a
     * number of subdomains that (to me) are really distinct and probably do not
     * represent the same (logical) web visit.  Additionally, some of these
     * sites are [near] exclusively used by automated tools instead of actual
     * people and thus its important to differentiate these sites so they can be
     * filtered out by remap_host.
     *
     * Finally, we also leave all three labels intact if that second-to-last
     * label is 'co' and the last label is only two characters.  This implies
     * that its probably an international domain, like foo.co.uk so we need the
     * third label to differentiate sites from this country.
     */
    char *head = key->host;
    int labels = 1;
    int international = 0;
    do {
        char *first_dot = strchr(head, '.');
        if (first_dot == NULL) break;
        labels = 2;
        char *second_dot = strchr(first_dot+1, '.');
        if (second_dot == NULL) break;
        labels = 3;
        while (1) {
            char *third_dot = strchr(second_dot+1, '.');
            if (third_dot == NULL) break;
            head = first_dot + 1;
            first_dot = second_dot;
            second_dot = third_dot;
        }

        if ((strncmp(first_dot, ".co", 3) == 0) && (strlen(second_dot) == 3))
            international = 1;
    } while (0);

    if ((labels == 3) && (!international)) {
        /* If not a special exception domain, strip bottom (third) label */
        if ((strstr(head, ".google.com") == NULL) &&
            (strstr(head, ".amazon.com") == NULL) &&
            (strstr(head, ".live.com") == NULL)) {

            char *dot = strchr(head, '.');
            if (dot != NULL) head = dot + 1;
        }
    }

    if (head != key->host)
        memmove(key->host, head, strlen(head) + 1);

    /*
     * try to parse the last label as an integer, it should be a top-level
     * domain (e.g. com, org) but if it parses as an integer the host name may
     * actually be an IP address.
     */
    char *last_dot = strrchr(key->host, '.');
    if (last_dot == NULL) {
        /* ??? */
        if (debug)
            PRINT_REJECTED_PACKET(h, req, key->src_ip, "host has no dots");
        free(key);
        return;
    }

    char *endptr = NULL;
    (void) strtol(last_dot + 1, &endptr, 10);
    if (endptr[0] == '\0') {
        /* last label is an integer - assume host is an IP (or just invalid) */
        if (debug)
            PRINT_REJECTED_PACKET(h, req, key->src_ip, "host is IP address");
        free(key);
        return;
    }

    /* finally, check if host should be remapped */
    const char *remapped = remap_host(key->host);
    if (remapped == NULL) {
        /* this host should be rejected completely */
        if (debug)
            PRINT_REJECTED_PACKET(h, req, key->src_ip, "blacklisted");
        free(key);
        return;
    }

    if (remapped != key->host)
        strlcpy(key->host, remapped, sizeof(key->host));

    u_char new_session = 0;
    struct web_session *elt = NULL;
    size_t keylen = sizeof(key->src_ip) + strlen(key->host);
    HASH_FIND(hh, sessions, key, keylen, elt);

    if (elt == NULL) {
        elt = malloc(sizeof(struct web_session));
        if (elt == NULL)
            err(1, "malloc(%d)", sizeof(struct web_session));
        elt->keyptr = key;
        new_session = 1;
        HASH_ADD_KEYPTR(hh, sessions, elt->keyptr, keylen, elt);
    } else {
        if (orion_time_cmp(&(h->ts), &(elt->session_timeout)) <= 0) {
            /*
             * ok, h->ts is prior to when the session would timeout, so we treat
             * it as being part of the same session
             */
        } else {
            /*
             * h->ts is after the prior session would have timed out, so we
             * treat this request as starting a new session
             */
            new_session = 1;
        }
    }

    static struct timeval timeout = { WEBREQ_SESSION_MAXDUR, 0 };
    orion_time_add(&(h->ts), &timeout, &(elt->session_timeout));

    if (debug) {
        PRINT_SESSION_PACKET(h, req, key->src_ip, key->host, new_session);
    } else {
        if (new_session)
            printf("%s\n", key->host);
    }

    free(req);
}

/*
 * This function "remaps" HTTP host values to make session tracking easier.  For
 * example, the host value "ytimg.com" (which is a YouTube image server) is
 * remapped to "youtube.com".  This way, a request to ytimg.com followed by a
 * request to youtube.com from the same IP will be tracked as a single web
 * session to youtube.com.  If the return value is NULL then the host is a "non-
 * specific" host, meaning it can serve content on any website.  Typically these
 * are adware servers or the like.
 */
static const char *
remap_host(const char *host)
{
    /*
     * list of google.com, amazon.com, and live.com domains from which page
     * requests DO represent "real" user sessions - there are so many domains
     * that do NOT (e.g. they serve ads), its easier to whitelist them than to
     * blacklist them
     */
    static const char *google_whitelist[] = {
        "www.google.com",
        "mail.google.com",
        "news.google.com",
        "images.google.com",
        "spreadsheets.google.com",
        "maps.google.com",
        "docs.google.com",
        "books.google.com",
        "video.google.com",
        "google.com",
        "scholar.google.com",
        "groups.google.com",
        "blogsearch.google.com",
        NULL
    };

    const char *amazon_whitelist[] = {
        "www.amazon.com",
        NULL
    };

    const char *live_whitelist[] = {
        "mail.live.com",  /* hotmail */
        NULL
    };

    const char **whitelist = NULL;

    char *loc = strstr(host, ".google.com");
    if (loc != NULL)
        whitelist = google_whitelist;

    if (loc != NULL) {
        loc = strstr(host, ".live.com");
        if (loc != NULL)
            whitelist = live_whitelist;
    }

    if (loc != NULL) {
        loc = strstr(host, ".amazon.com");
        if (loc != NULL)
            whitelist = amazon_whitelist;
    }

    if (loc != NULL) {
        for (int i=0; whitelist[i] != NULL; i++) {
            if (strcmp(host, whitelist[i]) == 0)
                return host;
        }

        /* host is not in the whitelist - reject it */
        return NULL;
    }

    loc = strstr(host, ".live.com");
    if (loc != NULL) {
        const char *whitelist[] = { "mail.live.com",  /* hotmail */
                                    NULL };

        for (int i=0; whitelist[i] != NULL; i++) {
            if (strcmp(host, whitelist[i]) == 0)
                return host;
        }

        /*
         * at this point, we know that host ends with '.live.com', but is not
         * in the whitelist; we assume that we should reject this host
         */
        return NULL;
    }


    static struct mapped_string *mappings = NULL;

    if (mappings == NULL) {
        /* initialize mappings */
        const char *srcs[] = { "fbcdn.net",  /* Facebook CDN */
                               "ytimg.com",  /* YouTube images */
                               "images-amazon.com",
                               "turner.com",  /* CDN for cnn.com*/
                               NULL };
        const char *dsts[] = { "facebook.com",
                               "youtube.com",
                               "amazon.com",
                               "cnn.com",
                               NULL };

        for (int i=0; srcs[i] != NULL; i++) {
            struct mapped_string *mapping = malloc(sizeof(struct mapped_string));
            if (mapping == NULL) err(1, "malloc(%d)", sizeof(struct mapped_string));
            strlcpy(mapping->src, srcs[i], sizeof(mapping->src));
            strlcpy(mapping->dst, dsts[i], sizeof(mapping->dst));
            HASH_ADD_STR(mappings, src, mapping);
        }

        const char *blacklist[] = {
            "doubleclick.net",  /* ads/tracking */
            "googlesyndication.com",  /* ads/tracking */
            "google-analytics.com",  /* ads/tracking */
            "2mdn.net",   /* ads/tracking */
            "atdmt.com",  /* ads/tracking */
            "wii.com",   /* most requests from Wii games */
            "gstatic.com",  /* google static content */
            "yimg.com",  /* Yahoo images (part of ads?) */
            "quantserve.com", /* ads/tracking */
            "scorecardresearch.com", /* ads/tracking */
            "yieldmanager.com", /* ads/tracking */
            "brightcove.com",   /* video hosting */
            "siteadvisor.com",  /* security checking */
            "edgesuite.net",    /* Akamai content hosting */
            "advertising.com",  /* ads/tracking */
            "windowsupdate.com",  /* software download */
            "revsci.net",  /* ads/tracking */
            "amazonaws.com", /* amazon web services */
            "addthis.com", /* widgets */
            "pointroll.com", /* ads/tracking */

            /*
             * I'd like to map this to wikipedia.org but the
             * traces are too inconsistent to support this
             */
            "wikimedia.org",
            NULL };

        for (int i=0; blacklist[i] != NULL; i++) {
            struct mapped_string *mapping = malloc(sizeof(struct mapped_string));
            if (mapping == NULL) err(1, "malloc(%d)", sizeof(struct mapped_string));
            strlcpy(mapping->src, blacklist[i], sizeof(mapping->src));
            strlcpy(mapping->dst, "", sizeof(mapping->dst));
            HASH_ADD_STR(mappings, src, mapping);
        }
    }

    struct mapped_string *mapping;
    HASH_FIND_STR(mappings, host, mapping);

    if (mapping == NULL)
        return host;  /* no mapping required */

    if (strlen(mapping->dst) == 0)
        return NULL;  /* host is rejected */

    /* return mapping */
    return mapping->dst;
}
