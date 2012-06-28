#ifndef CLICK_NUMBEREDSWITCH_HH
#define CLICK_NUMBEREDSWITCH_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c

NumberedSwitch

=s numbered

sends packet stream to output chosen per-packet by packet number annotation

*/

class NumberedSwitch : public Element { public:

    NumberedSwitch();
    ~NumberedSwitch();

    const char *class_name() const		{ return "NumberedSwitch"; }
    const char *port_count() const		{ return "1/-"; }
    const char *processing() const		{ return PUSH; }

    void push(int, Packet *);
};

CLICK_ENDDECLS
#endif
