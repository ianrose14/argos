#ifndef CLICK_BSSIDFILTER_HH
#define CLICK_BSSIDFILTER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
CLICK_DECLS

/*
=c
BSSIDFilter()

*/

class BSSIDFilter : public Element {
public:
    BSSIDFilter();
    ~BSSIDFilter();

    const char *class_name() const	{ return "BSSIDFilter"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

private:
    EtherAddress _bssid;
};

CLICK_ENDDECLS
#endif
