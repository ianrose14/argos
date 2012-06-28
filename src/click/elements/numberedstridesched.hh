#ifndef CLICK_NUMBEREDSTRIDESCHED_HH
#define CLICK_NUMBEREDSTRIDESCHED_HH
#include <click/element.hh>
#include "stridesched.hh"
CLICK_DECLS

/*
 * like StrideSched, but sets packet number to input port
 */

class NumberedStrideSched : public StrideSched {
 public:
    NumberedStrideSched();
    ~NumberedStrideSched();

    const char *class_name() const		{ return "NumberedStrideSched"; }

    Packet *pull(int port);
};

CLICK_ENDDECLS
#endif
