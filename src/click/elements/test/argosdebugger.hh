#ifndef CLICK_ARGOSDEBUGGER_HH
#define CLICK_ARGOSDEBUGGER_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS

/*
=c
ArgosDebugger()
*/

class ArgosDebugger : public Element {
public:
    ArgosDebugger();
    ~ArgosDebugger();

    const char *class_name() const	{ return "ArgosDebugger"; }
    const char *port_count() const	{ return PORTS_1_1; }

    int configure(Vector<String>&, ErrorHandler *);
    int initialize(ErrorHandler *);
    void run_timer(Timer*);
    Packet *simple_action(Packet*);

    enum DEBUG_MODE { MODE_TIMESTAMP, MODE_USE_COUNT, MODE_OWNER, MODE_PKT_CHAIN,
                      MODE_PKT_NUMBER };

private:
    Timer _timer;
    Timestamp _interval;
    String _label;
    enum DEBUG_MODE _mode;
};

CLICK_ENDDECLS
#endif
