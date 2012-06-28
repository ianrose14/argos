#ifndef CLICK_ARGOSQUEUEWATCHER_HH
#define CLICK_ARGOSQUEUEWATCHER_HH
#include <click/element.hh>
#include <click/hashmap.hh> 
#include <click/string.hh>
#include <click/timer.hh>
#include "../loghandler.hh"
#include "../systeminfo.hh"
CLICK_DECLS

/*
=c

ArgosQueueWatcher

*/

class ArgosQueueWatcher : public Element {
public:
    ArgosQueueWatcher();
    ~ArgosQueueWatcher();

    const char *class_name() const	{ return "ArgosQueueWatcher"; }
    const char *port_count() const	{ return "-/-"; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void run_timer(Timer*);

private:
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    Timer _timer;
    Timestamp _interval;

    struct {
        const Handler *in_count;
        const Handler *in_bytecount;
        Element *in_elt;

        const Handler *out_count;
        const Handler *out_bytecount;
        Element *out_elt;
    } OutQueueCounts;

    // SystemInfo element
    SystemInfo *_sysinfo;

    // bytecount handler for sent data
    const Handler *_sent_bytecount_hdlr;
    Element *_sent_elt;

    // underflow accumulator for the sent data bytecount
    uint64_t _sent_bytecount_add;

    // bytecount handler for received data
    const Handler *_recv_bytecount_hdlr;
    Element *_recv_elt;

    // underflow accumulator for the received data bytecount
    uint64_t _recv_bytecount_add;

    Vector<String> _queue_names;

    // just used to temporarily hold handler names between configure() and
    // initialize()
    String _sysinfo_elt_name;

    Logger *_log;
};

CLICK_ENDDECLS
#endif
