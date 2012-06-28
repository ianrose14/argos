#ifndef CLICK_ADJUSTTIMESTAMP_HH
#define CLICK_ADJUSTTIMESTAMP_HH
#include <click/element.hh>
#include "argos/anno.h"  // for argos_sniff struct definition
CLICK_DECLS

/*
=c
AdjustTimestamp()

=s Argos

Modify packet's timestamp annotations.

=d
Modify packet's timestamp annotations.

*/

class AdjustTimestamp : public Element {
public:
    AdjustTimestamp();
    ~AdjustTimestamp();

    const char *class_name() const	{ return "AdjustTimestamp"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

private:
    Timestamp _delta;
};

CLICK_ENDDECLS
#endif
