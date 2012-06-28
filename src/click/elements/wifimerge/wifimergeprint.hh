#ifndef CLICK_WIFIMERGEPRINT_HH
#define CLICK_WIFIMERGEPRINT_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
WifiMergePrint()

=s Argos

Prints wifi-merge header from front of packets.

=d
Prints wifi-merge header from front of packets.

*/

class WifiMergePrint : public Element {
public:
    WifiMergePrint();
    ~WifiMergePrint();

    const char *class_name() const	{ return "WifiMergePrint"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet*);

private:
    String _label;
    bool _compact;
    bool _detailed;
    bool _ctime;
};

CLICK_ENDDECLS
#endif
