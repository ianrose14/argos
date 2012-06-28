#ifndef CLICK_IPUTIL_HH
#define CLICK_IPUTIL_HH

#include <click/error.hh>
#include <click/ipaddress.hh>
#include <click/string.hh>
CLICK_DECLS

/*
 * Method Declarations
 */

inline int ip_lookup_address(const String&, IPAddress*, ErrorHandler*);

int ip_lookup_address(const String&, uint16_t, int, struct sockaddr_in*,
    ErrorHandler*);

int
ip_lookup_hostname(const IPAddress &, uint16_t, String *, ErrorHandler *);

/*
 * Definitions of inlined functions
 */

int
ip_lookup_address(const String &host, IPAddress *ipaddr, ErrorHandler *errh)
{
    struct sockaddr_in sin;
    if (ip_lookup_address(host, 0, SOCK_DGRAM, &sin, errh) != 0)
        return -1;

    *ipaddr = IPAddress(sin.sin_addr);
    return 0;
}

CLICK_ENDDECLS
#endif
