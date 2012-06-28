#ifndef CLICK_ARGOSRADIOTAPENCAP_HH
#define CLICK_ARGOSRADIOTAPENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * ArgosRadiotapEncap()
 */

class ArgosRadiotapEncap : public Element {
public:
    ArgosRadiotapEncap();
    ~ArgosRadiotapEncap();

    const char *class_name() const	{ return "ArgosRadiotapEncap"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    Packet *simple_action(Packet *);
};

CLICK_ENDDECLS
#endif
