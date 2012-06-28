#ifndef CLICK_SPLITFIRST_HH
#define CLICK_SPLITFIRST_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
SplitFirst()

=s Argos

*/

class SplitFirst : public Element {
public:
    SplitFirst();
    ~SplitFirst();

    const char *class_name() const	{ return "SplitFirst"; }
    int configure(Vector<String> &, ErrorHandler *);
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const      { return PUSH; }
    const char *flags() const           { return "S0"; }

    void push(int, Packet*);

private:
    uint32_t _count;
    uint32_t _limit;
};

CLICK_ENDDECLS
#endif
