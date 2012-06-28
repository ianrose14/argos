#ifndef CLICK_WIFIMERGEDECAP_HH
#define CLICK_WIFIMERGEDECAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
WifiMergeDecap()

=s Argos

Strip wifi-merge header from packets.

=d
Strip wifi-merge header from packets.

*/

class WifiMergeDecap : public Element {
public:
    WifiMergeDecap();
    ~WifiMergeDecap();

    const char *class_name() const	{ return "WifiMergeDecap"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    Packet *simple_action(Packet*);
};

CLICK_ENDDECLS
#endif
