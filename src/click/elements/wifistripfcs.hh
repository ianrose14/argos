#ifndef CLICK_WIFISTRIPFCS_HH
#define CLICK_WIFISTRIPFCS_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
WifiStripFCS()

=s Wifi

Strip any trailing FCS from 802.11 frames.

=d
Strip any trailing FCS from 802.11 frames.

*/

class WifiStripFCS : public Element {
public:
    WifiStripFCS();
    ~WifiStripFCS();

    const char *class_name() const	{ return "WifiStripFCS"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

private:
    bool _has_anno;
    uint8_t _anno;
};

CLICK_ENDDECLS
#endif
