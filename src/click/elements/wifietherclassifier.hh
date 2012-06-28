#ifndef CLICK_WIFIETHERCLASSIFIER_HH
#define CLICK_WIFIETHERCLASSIFIER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
CLICK_DECLS

/*
=c
WifiEtherClassifier()

=s Argos

Push a set header onto packets.

=d
Push a set header onto packets.

*/

class WifiEtherClassifier : public Element {
public:
    WifiEtherClassifier();
    ~WifiEtherClassifier();

    const char *class_name() const	{ return "WifiEtherClassifier"; }
    const char *port_count() const	{ return "1/-"; }
    const char *processing() const      { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

private:
    Vector<int32_t> _patterns;
};

CLICK_ENDDECLS
#endif
