/*
 * timestampsort.{cc,hh} -- buffer and order 802.11 frames by timestamp.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "timestampsort.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include "argos/anno.h"

CLICK_DECLS

#define TIMESTAMPSORT_INIT_HEAPSIZE 1024
#define TIMESTAMPSORT_MIN_PAUSE_MS 10

// custom HEAP_COMPARE definition to compare Packet pointers
#undef HEAP_COMPARE
#define HEAP_COMPARE(a, b) ((a)->timestamp_anno() <= (b)->timestamp_anno() ? -1 : 1)

#ifndef min
#define min(a, b) (a <= b ? a : b)
#endif

TimestampSort::TimestampSort()
    : _timer(this), _heap(NULL), _verbose(false), _output_ordered(0),
      _output_late(0), _drop_late_packets(false)
{
    _timeout = Timestamp(TIMESTAMPSORT_TIMEOUT);
}

TimestampSort::~TimestampSort()
{
    if (_heap != NULL) {
        while (HEAP_COUNT(_heap) > 0) {
            Packet *p = NULL;
            HEAP_EXTRACT_ROOT(_heap, Packet*, p);
            p->kill();
        }
        HEAP_DESTROY(_heap);
    }
}

enum { H_HEAP_SIZE, H_OUTPUT_ORDERED, H_OUTPUT_LATE };

void
TimestampSort::add_handlers()
{
    add_read_handler("heap_size", read_handler, (void*)H_HEAP_SIZE);
    add_read_handler("output_ordered", read_handler, (void*)H_OUTPUT_ORDERED);
    add_read_handler("output_late", read_handler, (void*)H_OUTPUT_LATE);
}

int
TimestampSort::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "TIMEOUT", 0, cpTimestamp, &_timeout,
            "VERBOSE", 0, cpBool, &_verbose,
            "DROPLATE", 0, cpBool, &_drop_late_packets,
            cpEnd) < 0)
        return -1;
    return 0;
}

int
TimestampSort::initialize(ErrorHandler *)
{
    HEAP_CREATE(TIMESTAMPSORT_INIT_HEAPSIZE, sizeof(Packet *), _heap);
    _timer.initialize(this);
    _timer.schedule_now();

    return 0;
}

void
TimestampSort::push(int, Packet *p)
{
    Timestamp elapsed = Timestamp::now() - p->timestamp_anno();
    if (elapsed >= _timeout) {
        if (_verbose) {
            const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
            const struct argos_sniff *sniff = (const struct argos_sniff *)anno_ptr;

            if (sniff->magic == ARGOS_SNIFF_MAGIC) {
                click_chatter("%s: packet received %s late from %s (ts=%s)",
                    name().c_str(), elapsed.unparse().c_str(),
                    IPAddress(sniff->sniffer).unparse().c_str(),
                    p->timestamp_anno().unparse().c_str());
            } else {
                click_chatter("%s: packet received %s late (ts=%s)",
                    name().c_str(), elapsed.unparse().c_str(),
                    p->timestamp_anno().unparse().c_str());
            }
        }

        if (_drop_late_packets) {
            p->kill();
        } else {
            output(0).push(p);
            _output_late++;
        }
    } else {
        HEAP_ADD(_heap, Packet*, p);
    }
}

void
TimestampSort::run_timer(Timer*)
{
    Timestamp now = Timestamp::now();

    while (HEAP_COUNT(_heap) > 0) {
        Packet *minpkt = NULL;
        HEAP_ROOT(_heap, Packet*, minpkt);

        Timestamp send_time = minpkt->timestamp_anno() + _timeout;
        if (send_time > now)
            break;

        HEAP_EXTRACT_ROOT(_heap, Packet*, minpkt);

        output(0).push(minpkt);
        _output_ordered++;
    }

    // Click does not deal well with very frequent timer firings, so we can't do
    // the obvious here, which is to schedule the timer to next fire at
    // (minpkt->timestamp_anno() + _timeout).  Instead, we simply tick at
    // regular intervals, each time outputting all packets that have waited long
    // enough.  Although this means some packets are delayed slightly longer
    // than the element's specified timeout, this is ok because this element
    // only tries to *sort* packets, not necessarily output them at the exact
    // same rate that they were captured.
    _timer.reschedule_after_msec(TIMESTAMPSORT_MIN_PAUSE_MS);
}

String
TimestampSort::read_handler(Element *e, void *thunk)
{
    const TimestampSort *elt = static_cast<TimestampSort *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_HEAP_SIZE:
        return String(HEAP_COUNT(elt->_heap));
    case H_OUTPUT_ORDERED:
        return String(elt->_output_ordered);
    case H_OUTPUT_LATE:
        return String(elt->_output_late);
    default:
        return "internal error (bad thunk value)";
    }
}

// restore default HEAP_COMPARE definition
#undef HEAP_COMPARE
#define HEAP_COMPARE(a, b) HEAP_DEFAULT_COMPARE(a, b)

CLICK_ENDDECLS
EXPORT_ELEMENT(TimestampSort)
