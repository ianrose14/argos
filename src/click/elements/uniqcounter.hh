#ifndef CLICK_UNIQCOUNTER_HH
#define CLICK_UNIQCOUNTER_HH
#include <click/element.hh>
#include <click/ewma.hh>
#include <click/hashmap.hh>
CLICK_DECLS

/*
=c

UniqCounter([I<keywords COUNT_CALL, BYTE_COUNT_CALL>])

=s counters

measures unique counts of some packet offset

=d

Passes packets unchanged from its input to its output, maintaining a running
count of the number of unique instances of the value some packet offset

*/

class ByteString;

class UniqCounter : public Element {
public:
    UniqCounter();
    ~UniqCounter();

    const char *class_name() const		{ return "UniqCounter"; }
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

    counter_t _count;
    rate_t _rate;
    size_t _offset;
    u_char _fieldlen;
    bool _filter_packets;
    HashMap<ByteString, int> _uniqs;

    static String read_handler(Element *, void *);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);
};

class ByteString {
public:
    ByteString(const u_char *, int);
    ByteString(const ByteString &);
    ~ByteString();

    inline size_t hashcode() const { return _hashcode; }
    String unparse() const;

    friend bool
    operator==(const ByteString &a, const ByteString &b);

protected:
    u_char *_data;
    int _len;
    size_t _hashcode;
};

inline bool
operator==(const ByteString &a, const ByteString &b)
{
    return (a._len == b._len) && (memcmp(a._data, b._data, a._len) == 0);
}

CLICK_ENDDECLS
#endif
