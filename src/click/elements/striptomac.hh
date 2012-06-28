#ifndef CLICK_STRIPTOMAC_HH
#define CLICK_STRIPTOMAC_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 *
 * StripToMACHeader()
 *
 * =s basicmod
 *
 * strips everything preceding MAC header
 *
 * =d
 *
 * Strips any data preceding the MAC header from every passing packet.
 * Requires a MAC header annotation, such as an IP header annotation,
 * on every packet.
 * If the packet's MAC header annotation points before the start of the
 * packet data, then StripToMACHeader will move the packet data pointer
 * back, to point at the MAC header.
 *
 * =a Strip
 */

class StripToMACHeader : public Element { public:

    StripToMACHeader();
    ~StripToMACHeader();

    const char *class_name() const	{ return "StripToMACHeader"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const	{ return AGNOSTIC; }

    Packet *simple_action(Packet *);

};

CLICK_ENDDECLS
#endif
