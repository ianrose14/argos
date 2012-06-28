/*
 * Author: Ian Rose
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* local includes */
#include "async.h"
#include "circbuf.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

#define PROGNAME "fakeserver"
#define THRESH 3 /* seconds */

/**********************/
/*  STATIC VARIABLES  */
/**********************/

enum argos_net_pkt_types {
    ARGOS_NET_NULL_MSGTYPE=0,
    ARGOS_NET_HANDSHAKE_MSGTYPE=1,
    ARGOS_NET_PCAP_MSGTYPE=2,
    ARGOS_NET_STATS_MSGTYPE=3,
    ARGOS_NET_ERROR_MSGTYPE=4,
    ARGOS_NET_COMPRESS_MSGTYPE=5,
    ARGOS_NET_PING_MSGTYPE=6,  /* deprecated */
    ARGOS_NET_SETBPF_MSGTYPE=32,
    ARGOS_NET_SETCHAN_MSGTYPE=33,
    ARGOS_NET_CLOSECONN_MSGTYPE=34
};

struct argos_net_minimal_msg {
    uint16_t msgtype;
    uint16_t reserved;
    uint32_t msglen;
} __attribute__((__packed__));

struct argos_net_setbpf_msg {
    uint16_t msgtype;  /* must equal ARGOS_NET_SETBPF_MSGTYPE */
    uint16_t reserved;
    uint32_t msglen;
    /* next follows a pcap filter expression in string format */
} __attribute__((__packed__));

static struct argos_net_setbpf_msg setbpfcmd;

static int debug = 0;


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void accept_cb(int, void*);
static void read_cb(int, void*);


/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    /* default values for command line arguments */
    int portno = 9605;

    /* process command line options */
    const char *usage = "usage: " PROGNAME " [-g] [-p portno]\n";

    int c;
    while ((c = getopt(argc, argv, ":ghp:")) != -1) {
        switch (c) {
        case 'g':
            debug = 1;
            break;
        case 'h':
            printf("%s", usage);
            exit(0);
            break;
        case 'p':
            portno = atoi(optarg);
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

    setbpfcmd.msgtype = htons(ARGOS_NET_SETBPF_MSGTYPE);
    setbpfcmd.msglen = htonl(sizeof(struct argos_net_setbpf_msg));

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

    // if getaddrinfo returns 0, it should return a list of addrinfo structs
    assert(servinfo != NULL);
    assert(servinfo->ai_addrlen <= sizeof(struct sockaddr_in));

    struct sockaddr_in addr;
    memcpy(&addr, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) err(1, "socket");

    if (bind(sock, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
        err(1, "bind");

    if (listen(sock, 5) < 0)
        err(1, "listen");

    printf("listening for connections on %s:%d\n",
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    rv = async_add_read_fd(sock, 0, async_true_check, accept_cb, NULL);
    if (rv == -1)
        err(1, "async_add_read_fd");

    rv = async_loop();
    if (rv == -1) {
        err(1, "async_loop");
    } else if (rv == -2) {
        printf("async_loop terminated by async_breakloop\n");
    } else {
        printf("async_loop terminated on its own\n");
    }

    return 0;
}


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

static void
accept_cb(int fd, void *user)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int cli_fd = accept(fd, (struct sockaddr*)&addr, &len);
    if (cli_fd == -1) err(1, "accept");
    printf("%d: accepted connection from %s\n", cli_fd, inet_ntoa(addr.sin_addr));

    int rv = send(cli_fd, &setbpfcmd, sizeof(struct argos_net_setbpf_msg), 0);
    if (rv == -1) err(1, "send");
    if (rv < sizeof(struct argos_net_setbpf_msg))
        errx(1, "partial send (%d)", rv);

    struct circbuf *buf = circbuf_create((1024+102)*1024);
    if (buf == NULL) err(1, "circbuf_create");

    rv = async_add_read_fd(cli_fd, 0, async_true_check, read_cb, buf);
    if (rv == -1)
        err(1, "async_add_read_fd");
}

static void
read_cb(int fd, void *user)
{
    struct circbuf *buf = (struct circbuf*)user;

    ssize_t space = circbuf_writable(buf);
    assert(space > 0);

    ssize_t len = recv(fd, circbuf_tail(buf), space, 0);
    if (len == -1) err(1, "recv");

    struct timeval now;
    gettimeofday(&now, NULL);

    if (len == 0) {
        printf("EOF from fd %d\n", fd);
        int rv = close(fd);
        if (rv != 0) warn("close(%d)", fd);
        rv = async_remove_fd(fd);
        if (rv == -1) err(1, "async_remove_fd");
        return;
    }

    int rv = circbuf_tailup(buf, len);
    if (rv == -1) err(1, "circbuf_tailup");

    if (debug) printf("%d: recv %d bytes (requested %d)\n", fd, len, space);
    
    while (circbuf_len(buf) >= sizeof(struct argos_net_minimal_msg)) {
        struct argos_net_minimal_msg header;
        int rv = circbuf_read(buf, &header, sizeof(header));
        assert(rv == 0);
        if (circbuf_unread(buf, sizeof(header)) != 0)
            err(1, "circbuf_unread");

        uint16_t msgtype = ntohs(header.msgtype);
        uint32_t msglen = ntohl(header.msglen);

        /* just quit out if entire message not yet received */
        if (circbuf_len(buf) < msglen)
            if (debug) printf("%d: still waiting on %d bytes for msg type %d (blen=%d)\n",
                fd, msglen - circbuf_len(buf), msgtype, circbuf_len(buf));
        if (circbuf_len(buf) < msglen) return;

        switch (msgtype) {
        case ARGOS_NET_NULL_MSGTYPE:
            if (debug) printf("%d: NULL (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_HANDSHAKE_MSGTYPE:
            if (debug) printf("%d: Handshake (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_PCAP_MSGTYPE:
            if (debug) printf("%d: Pcap (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_STATS_MSGTYPE:
            if (debug) printf("%d: Stats (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_ERROR_MSGTYPE:
            if (debug) printf("%d: Error (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_COMPRESS_MSGTYPE:
            if (debug) printf("%d: Compress (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_PING_MSGTYPE:
            if (debug) printf("%d: Ping (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_SETBPF_MSGTYPE:
            if (debug) printf("%d: SetBPF (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_SETCHAN_MSGTYPE:
            if (debug) printf("%d: SetChan (msglen=%d)\n", fd, msglen);
            break;
        case ARGOS_NET_CLOSECONN_MSGTYPE:
            if (debug) printf("%d: CloseConn (msglen=%d)\n", fd, msglen);
            break;
        default:
            warnx("unknown message %d (msglen=%d) from fd %d\n", msgtype,
                msglen, fd);
            abort();
            break;
        }

        rv = circbuf_discard(buf, msglen);
        assert(rv == 0);
    }
}
