#ifndef CLICK_TIMESTAMPSORT_HH
#define CLICK_TIMESTAMPSORT_HH
#include <click/element.hh>
#include <click/packet.hh>
#include <click/timer.hh>
#include <click/timestamp.hh>
#include "binheap.h"
CLICK_DECLS

/*
=c
TimestampSort()

=s Argos

Buffer and order 802.11 frames by timestamp.

=d
Buffer and order 802.11 frames by timestamp.

*/


/* how long we hold onto a packet before outputting it */
#define TIMESTAMPSORT_TIMEOUT  5  /* sec */

class TimestampSort : public Element {
public:
    TimestampSort();
    ~TimestampSort();

    const char *class_name() const	{ return "TimestampSort"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const      { return PUSH; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet *);
    void run_timer(Timer *);

private:
    static String read_handler(Element*, void*);

    Timer _timer;
    binheap_t *_heap;
    bool _verbose;

    // how long to wait before a packet is output
    Timestamp _timeout;

    // stats
    uint32_t _output_ordered, _output_late;

    // whether to drop (if true) or pass on (if false) packets received after
    // their output time (i.e. badly delayed)
    bool _drop_late_packets;
};

CLICK_ENDDECLS
#endif
