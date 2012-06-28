#ifndef CLICK_ARGOSQUERY_HH
#define CLICK_ARGOSQUERY_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
ArgosQuery()

=s Argos

Registers a query with the system.

=d
Registers a query with the system.  A query consists of a unique ID, a priority
level (the legal range is system-defined but is typically 0-15, inclusive), a
BPF filter expression (which defaults to ""), and a click router configuration
fragment (which is merged with the basic Argos router configuration to create a
complete configuration).
*/

class ArgosQuery : public Element {
public:
    ArgosQuery();
    ~ArgosQuery();

    const char *class_name() const	{ return "ArgosQuery"; }
    // configure and initialize before (most) other elements
    int configure_phase() const         { return CONFIGURE_PHASE_DEFAULT-1; }
    const char *port_count() const	{ return PORTS_0_0; }

    int configure(Vector<String>&, ErrorHandler *);
    int initialize(ErrorHandler *);

private:
    String _query;
    uint8_t _priority;
    Vector<String> _handler_names;
};

CLICK_ENDDECLS
#endif
