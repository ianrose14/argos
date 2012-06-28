#ifndef CLICK_SETSNIFFER_HH
#define CLICK_SETSNIFFER_HH
#include <click/element.hh>
#include "argos/anno.h"  // for argos_sniff struct definition
CLICK_DECLS

/*
=c
SetSniffer()

=s Argos

Push a set header onto packets.

=d
Push a set header onto packets.

*/

class SetSniffer : public Element {
public:
    SetSniffer();
    ~SetSniffer();

    const char *class_name() const	{ return "SetSniffer"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

    static int parse_sniffer_id(const Packet*, int32_t*, ErrorHandler*);

private:
    struct argos_sniff _hdr;
};

CLICK_ENDDECLS
#endif
