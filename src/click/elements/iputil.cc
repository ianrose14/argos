/*
 * iputil.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include <click/straccum.hh>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "iputil.hh"
CLICK_DECLS


int
ip_lookup_address(const String &host, uint16_t port, int socktype,
    struct sockaddr_in *addr, ErrorHandler *errh)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;

    char portstr[32];
    snprintf(portstr, sizeof(portstr), "%hu", port);

    int rv = getaddrinfo(host.c_str(), portstr, &hints, &servinfo);
    if (rv != 0)
        return errh->error("getaddrinfo: %s", gai_strerror(rv));

    // if getaddrinfo returns 0, it should return a list of addrinfo structs
    assert(servinfo != NULL);
    assert(servinfo->ai_addrlen <= sizeof(struct sockaddr_in));

    memcpy(addr, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);
    return 0;
}

int
ip_lookup_hostname(const IPAddress &ip, uint16_t port, String *s,
    ErrorHandler *errh)
{
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);  // I doubt this matters, but just in case...
    sin.sin_addr = ip.in_addr();

    char host[NI_MAXHOST];
    int err = getnameinfo((struct sockaddr*)&sin, sizeof(sin), host, sizeof(host),
        NULL, 0, NI_NAMEREQD);

    if (err == 0) {
        // got a hostname!
        *s = String(host);
        return 0;
    }
    else if (err == EAI_NONAME) {
        // this means that no name could be found - perhaps there is no DNS
        // record for this IP address (no error reported)
        return -1;
    }
    else {
        return errh->error("getnameinfo: %s", gai_strerror(err));
    }
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(IPUtil)
