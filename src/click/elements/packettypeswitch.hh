#ifndef CLICK_PACKETTYPESWITCH_HH
#define CLICK_PACKETTYPESWITCH_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
PacketTypeSwitch()

=s Argos

*/

class PacketTypeSwitch : public Element {
public:
    PacketTypeSwitch();
    ~PacketTypeSwitch();

    const char *class_name() const	{ return "PacketTypeSwitch"; }
    const char *port_count() const	{ return "1/-"; }
    const char *processing() const      { return PUSH; }

    void push(int, Packet*);
};

CLICK_ENDDECLS
#endif
