#ifndef CLICK_WIFIMERGEUNSTRIP_HH
#define CLICK_WIFIMERGEUNSTRIP_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
WifiMergeUnstrip()

=s Argos

Strip wifi-merge header from packets.

=d
Strip wifi-merge header from packets.

*/

class WifiMergeUnstrip : public Element {
public:
    WifiMergeUnstrip();
    ~WifiMergeUnstrip();

    const char *class_name() const	{ return "WifiMergeUnstrip"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    void push(int, Packet*);
};

CLICK_ENDDECLS
#endif
