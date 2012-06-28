#ifndef CLICK_SSIDFILTER_HH
#define CLICK_SSIDFILTER_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS

/*
=c
SSIDFilter()

*/

class SSIDFilter : public Element {
public:
    SSIDFilter();
    ~SSIDFilter();

    const char *class_name() const	{ return "SSIDFilter"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

private:
    String _ssid;
    bool _ignore_case;
};

CLICK_ENDDECLS
#endif
