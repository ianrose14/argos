/*
 * Author: Ian Rose
 * Date Created: Sep 3, 2009
 *
 * Like netcat, but allows user to specify the send() size and to set the
 * TCP_NODELAY socket option.
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>

/* local includes */
#include "orion/net.h"
#include "orion/time.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

#define XFER_BUFSIZE (1024*1024)         /* 1 MB */
#define DEF_UDP_SENDSIZE 1472       /* approx max */
#define DEF_TCP_SENDSIZE (32*1024)  /* 32KB */


/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    /* default values for command line arguments */
    int debug = 0;
    int nodelay = 0;
    int use_udp = 0;
    int sendsize = -1;
    const char *readfile = NULL;

    /* process command line options */
    const char *usage =
        "usage: netspam [-gnu] [-s size] HOST PORT\n";

    int c;
    while ((c = getopt(argc, argv, ":ghns:u")) != -1) {
        switch (c) {
        case 'g':
            debug = 1;
            break;
        case 'h':
            printf(usage);
            printf(
                "    -g  enable debugging output\n"
                "    -h  print usage information and quit\n"
                "    -n  'no delay' (disable Nagle algorithm)\n"
                "    -r  send a file (or stdin) instead of junk\n"
                "    -s  amount of data to send per send() call\n"
                "    -u  use UDP instead of TCP\n");
            exit(0);
            break;
        case 'n':
            nodelay = 1;
            break;
        case 'r':
            errx(1, "not supported");
            readfile = optarg;
            break;
        case 's':
            sendsize = atoi(optarg);
            break;
        case 'u':
            use_udp = 1;
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

    if (argc != 2) {
        printf(usage);
        exit(0);
    }

    const char *hostname = argv[0];
    int portno = atoi(argv[1]);

    if (sendsize == -1)
        sendsize = use_udp ? DEF_UDP_SENDSIZE : DEF_TCP_SENDSIZE;

    int socktype = use_udp ? SOCK_DGRAM : SOCK_STREAM;
    int sock = socket(AF_INET, socktype, 0);
    if (sock == -1)
        err(1, "socket");

    struct sockaddr_in addr;
    if (orion_net_lookup_inaddr(hostname, portno, socktype, &addr) != 0)
        err(1, "orion_net_lookup_inaddr");

    if (!use_udp) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
            err(1, "connect");
    }

    if (nodelay) {
        if (use_udp)
            errx(1, "cannot specify both -n and -u options");
        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
            err(1, "setsockopt(TCP_NODELAY)");
    }

    uint64_t total_sent = 0;
    char buf[XFER_BUFSIZE];
    size_t buf_head = 0;
    size_t buf_len = 0;

    assert(sizeof(buf) >= sendsize);
    fd_set zeroset;
    FD_ZERO(&zeroset);

    struct timeval start;
    if (gettimeofday(&start, NULL) != 0)
        err(1, "gettimeofday");

    while (1) {
        buf_head = 0;
        buf_len = sizeof(buf);

        ssize_t to_send = (buf_len > sendsize) ? sendsize : buf_len;
        if (to_send == 0) break;

        ssize_t len;
        fd_set writeset = zeroset;

        if (use_udp) {
            len = sendto(sock, buf + buf_head, to_send, 0,
                (struct sockaddr*)&addr, sizeof(addr));
            if ((len == -1) && (errno == ENOBUFS)) {
                FD_SET(sock, &writeset);
                int rv = select(sock+1, NULL, &writeset, NULL, NULL);
                if (rv == -1) err(1, "select");
                assert(rv == 1);
                assert(FD_ISSET(sock, &writeset));
                len = 0;  /* suppress error handling further down */
            }
        } else {
            len = send(sock, buf + buf_head, to_send, 0);
            assert(len != 0);
        }

        if (len == -1)
            err(1, use_udp ? "sendto" : "send");

        if (debug)
            printf("sent %u bytes to socket (attempted %u)\n", len, to_send);

        if (len > 0) {
            assert(len <= buf_len);
            buf_head += len;
            buf_len -= len;
            total_sent += len;
        }
    }

    struct timeval end;
    if (gettimeofday(&end, NULL) != 0)
        err(1, "gettimeofday");

    struct timeval elapsed;
    orion_time_subtract(&end, &start, &elapsed);

    float secs = elapsed.tv_sec + (float)elapsed.tv_usec/1000000;
    printf("sent %llu bytes in %.2f seconds  (%.2f Mbit/s)\n", total_sent, secs,
        (8*total_sent/secs)/(1024*1024));

    assert(buf_len == 0);

    if (close(sock) != 0)
        err(1, "close");

    return 0;
}
