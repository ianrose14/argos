/*
 * Author: Ian Rose
 * Date Created: Jan 22, 2009
 *
 * Network-related utility functions.
 */

/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>  /* dependency of net/if_dl.h*/
#include <net/if_dl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>     /* must be included before net80211/ieee80211_ioctl.h */
#include <net80211/ieee80211_ioctl.h>
#include <netdb.h>
#include <ifaddrs.h>

/* local includes */
#include "orion/net.h"


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static int gaierr_to_errno(int gaierr);
static int get80211(const char * restrict ifname, int type, void *data, int len);
static int set80211(const char * restrict ifname, int type, const void *data, int len);


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* dummy socket, used for ioctls */
static int s = 0;

/*
 * channel information; we assume that this is constant, at least over the
 * lifetime of a process, so we just load it once and save it (for efficiency)
 */
static u_char channels_loaded = 0;
static struct ieee80211req_chaninfo chaninfo;


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

/*
 * Returns the 802.11 channel that the specified interface is currently tuned to,
 * or 0 if an error occurs.
 */
uint8_t
orion_net_get_channel(const char * restrict ifname)
{
    struct ieee80211_channel chan;
    if (get80211(ifname, IEEE80211_IOC_CURCHAN, &chan, sizeof(chan)) < 0)
        return 0;
    else
        return chan.ic_ieee;
}

/* look up a host by hostname & port, returning a sockaddr_in */
int
orion_net_lookup_inaddr(const char * restrict hostname, int port,
    int socktype, struct sockaddr_in * restrict sa)
{
    struct addrinfo hints, *servinfo;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;

    if (hostname == NULL) hints.ai_flags = AI_PASSIVE;

    const char *portstr = NULL;
    char cbuf[128];
    if (port != 0) {
        snprintf(cbuf, sizeof(cbuf), "%d", port);
        portstr = cbuf;
    }

    rv = getaddrinfo(hostname, portstr, &hints, &servinfo);
    if (rv != 0) {
        errno = gaierr_to_errno(rv);
        return -1;
    }

    /* if getaddrinfo returns 0, it should return a list of addrinfo structs */
    assert(servinfo != NULL);

    if (servinfo->ai_addrlen > sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        freeaddrinfo(servinfo);
        return -1;
    }

    memcpy(sa, servinfo->ai_addr, servinfo->ai_addrlen);
    sa->sin_port = htons(port);
    freeaddrinfo(servinfo);
    return 0;
}

/* look up a local network interface's hardware (MAC) address */
int
orion_net_lookup_macaddr(const char * restrict ifname,
    u_char * restrict mac_addr)
{
    struct ifaddrs *ifap_root, *ifap;
    if (getifaddrs(&ifap_root) == -1)
        return -1;

    ifap = ifap_root;

    for (ifap = ifap_root; ifap != NULL; ifap = ifap->ifa_next) {
        if ((strcmp(ifap->ifa_name, ifname) == 0) &&
            (ifap->ifa_addr->sa_family == AF_LINK)) {
            /* found the named interface */
            memcpy(mac_addr, LLADDR(((struct sockaddr_dl*)ifap->ifa_addr)), 6);
            freeifaddrs(ifap_root);
            return 0;
        }
    }
    
    /* named interface not found */
    freeifaddrs(ifap_root);
    errno = ENODEV;
    return -1;
}

/*
 * Sets the 802.11 channel of the specified interface.  Returns 0 on success and
 * -1 on error.
 */
int
orion_net_set_channel(const char * restrict ifname, uint8_t channel,
    char mode)
{
    if (!channels_loaded) {
        if (get80211(ifname, IEEE80211_IOC_CHANINFO, &chaninfo,
                sizeof(chaninfo)) < 0)
            return -1;
        channels_loaded = 1;
    }

    for (int i = 0; i < chaninfo.ic_nchans; i++) {
        const struct ieee80211_channel *c = &chaninfo.ic_chans[i];

        if (c->ic_ieee == channel) {
            if (mode == 'a' && (! IEEE80211_IS_CHAN_A(c)))
                continue;

            if (mode == 'b' && (! IEEE80211_IS_CHAN_B(c)))
                continue;

            if (mode == 'g' && (! IEEE80211_IS_CHAN_ANYG(c)))
                continue;

            return set80211(ifname, IEEE80211_IOC_CURCHAN, (void*)c,
                sizeof(struct ieee80211_channel));
        }
    }

    /* failed to find a matching channel */
    errno = ENODEV;  /* "operation not supported by device" */
    return -1;
}

/*
 * Binds a socket to the specified hostname and port.  If the hostname is NULL,
 * then the IP used is INADDR_ANY. reference:
 * http://beej.us/guide/bgnet/output/html/multipage/syscalls.html#bind
 */
int
orion_net_sockbind(int sock, const char * restrict hostname, int port)
{
    char portstr[16];
    struct addrinfo hints, *servinfo;
    int rv;

    snprintf(portstr, sizeof(portstr), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (hostname == NULL) {
        hints.ai_flags = AI_PASSIVE;   /* fill in IP for me */
        
        rv = getaddrinfo(NULL, portstr, &hints, &servinfo);
    } else {
        rv = getaddrinfo(hostname, portstr, &hints, &servinfo);
    }

    /* handle getaddrinfo return value */
    if (rv != 0) {
        errno = gaierr_to_errno(rv);
        return -1;
    }

    /* if getaddrinfo returns 0, it should return a list of addrinfo structs */
    assert(servinfo != NULL);

    rv = bind(sock, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);
    return rv;
}


/********************/
/*  STATIC METHODS  */
/********************/

/* maps getaddrinfo() return values to the "best" (closest) errno value */
static int
gaierr_to_errno(int gaierr)
{
    switch (gaierr) {
    case EAI_AGAIN:     /* temporary failure in name resolution */
        return EAGAIN;
    case EAI_BADFLAGS:  /* invalid value for ai_flags */
        return EINVAL;
    case EAI_BADHINTS:  /* invalid value for hints */
        return EINVAL;
    case EAI_FAIL:      /* non-recoverable failure in name resolution */
        return 0; /* really no good errno option for this one */
    case EAI_FAMILY:    /* ai_family not supported */
        return EAFNOSUPPORT;
    case EAI_MEMORY:    /* memory allocation failure */
        return ENOMEM;
    case EAI_NONAME:    /* hostname or servname not provided, or not known */
        return EINVAL;
    case EAI_OVERFLOW:  /* argument buffer overflow */
        return ENOBUFS;
    case EAI_PROTOCOL:  /* resolved protocol is unknown */
        return EPROTONOSUPPORT;
    case EAI_SERVICE:   /* servname not supported for ai_socktype */
        return EOPNOTSUPP;
    case EAI_SOCKTYPE:  /* ai_socktype not supported */
        return ESOCKTNOSUPPORT;
    case EAI_SYSTEM:    /* system error returned in errno */
        return errno;
    default:
        /* unexpected value */
        return EINVAL;
    }
}

/* modified from ifconfig/ifieee80211.c */
static int
get80211(const char * restrict ifname, int type, void *data, int len)
{
    if (s == 0) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == -1) return 0;
    }

    struct ieee80211req ireq;
    memset(&ireq, 0, sizeof(ireq));
    strlcpy(ireq.i_name, ifname, sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_data = data;
    ireq.i_len = len;
    return ioctl(s, SIOCG80211, &ireq);
}

/* modified from ifconfig/ifieee80211.c */
static int
set80211(const char * restrict ifname, int type, const void *data, int len)
{
    if (s == 0) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == -1) return 0;
    }
    
    struct ieee80211req ireq;
    memset(&ireq, 0, sizeof(ireq));
    strlcpy(ireq.i_name, ifname, sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_len = len;
    ireq.i_data = (void*)data;
    return ioctl(s, SIOCS80211, &ireq);
}
