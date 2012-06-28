#ifndef CLICK_COMPAREPACKETS_HH
#define CLICK_COMPAREPACKETS_HH
#include <click/element.hh>
#include <click/notifier.hh>
CLICK_DECLS

/*
=c

ComparePairs([I<keywords> TIMESTAMP])

=s test

compare packets in pairs

=d

ComparePairs compares packets pulled from the first input with packets
pulled from the second input.  Pairs are considered different if they have
different length, data, header offsets, or timestamp annotations.

Keyword arguments are:

=over 8

=item TIMESTAMP

Boolean.  If true, then ComparePairs will check packet timestamp
annotations.  Default is true.

=back

=h diffs read-only

Returns the number of different packet pairs seen.

=h diff_details read-only

Returns a text file showing how many different packet pairs ComparePairs has
seen, subdivided by type of difference.

=h all_same read-only

Returns "true" iff all packet pairs seen so far have been identical.

=a

PacketTest */

class ComparePairs : public Element { public:

    ComparePairs();
    ~ComparePairs();

    const char *class_name() const		{ return "ComparePairs"; }
    const char *port_count() const		{ return "2/0"; }
    const char *processing() const		{ return PULL; }
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();
    bool run_task(Task*);

  private:

    Packet *_p[2];
    NotifierSignal _signal;

    bool _timestamp : 1;

    uint32_t _ndiff;
    enum { D_LEN, D_DATA, D_TIMESTAMP, D_NETOFF, D_NETLEN, D_NETHDR,
	   D_MORE_PACKETS_0, D_MORE_PACKETS_1, D_LAST };
    uint32_t _diff_details[D_LAST];

    Task _task;

    void check(Packet *, Packet *);
    static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
