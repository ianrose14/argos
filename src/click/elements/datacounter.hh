#ifndef CLICK_DATACOUNTER_HH
#define CLICK_DATACOUNTER_HH
#include <click/element.hh>
#include <click/ewma.hh>
CLICK_DECLS

/*
=c

DataCounter()

=s counters

measures count of some packet offset

=d

Passes packets unchanged from its input to its output, maintaining a running
count of the value of some packet offset

*/

class DataCounter : public Element {
public:
    DataCounter();
    ~DataCounter();

    const char *class_name() const		{ return "DataCounter"; }
    const char *port_count() const		{ return PORTS_1_1; }
    const char *processing() const		{ return AGNOSTIC; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

    void reset();
  private:

#ifdef HAVE_INT64_TYPES
    typedef uint64_t counter_t;
    typedef RateEWMAX<RateEWMAXParameters<4, 4, uint64_t, int64_t> > rate_t;
#else
    typedef uint32_t counter_t;
    typedef RateEWMAX<RateEWMAXParameters<4, 4> > rate_t;
#endif

    counter_t _sum;
    rate_t _rate;
    size_t _offset;
    u_char _fieldlen;
    bool _big_endian;  // if false, then little endian

    static String read_handler(Element *, void *);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);
};

CLICK_ENDDECLS
#endif
