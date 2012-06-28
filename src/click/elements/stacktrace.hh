#ifndef CLICK_STACKTRACE_HH
#define CLICK_STACKTRACE_HH
#include <click/element.hh>
CLICK_DECLS

class StackTrace : public Element {
public:
    StackTrace();
    ~StackTrace();

    const char *class_name() const	{ return "StackTrace"; }
    // configure and initialize before (nearly) any other elements
    int configure_phase() const         { return CONFIGURE_PHASE_FIRST; }
    const char *port_count() const	{ return PORTS_0_0; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);

    static int print_stack_trace(int fd, int newline);

private:
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    enum { STACKTRACE_EXIT_SIG, STACKTRACE_EXIT_0, STACKTRACE_RAISE,
           STACKTRACE_RETURN } _action;

    Vector<int> _signals;
};

CLICK_ENDDECLS
#endif
