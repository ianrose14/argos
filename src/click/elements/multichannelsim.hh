#ifndef CLICK_MULTICHANNELSIM_HH
#define CLICK_MULTICHANNELSIM_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <pcap/pcap.h>

CLICK_DECLS

/*
=title MultiChannelSim

=c

MultiChannelSim()

*/

class MultiChannelSim : public Element {
public:
    MultiChannelSim();
    ~MultiChannelSim();

    const char *class_name() const	{ return "MultiChannelSim"; }
    const char *port_count() const	{ return "11/1-2"; }
    const char *processing() const	{ return PUSH; }

    void add_handlers();
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void push(int, Packet*);

    int get_stats(u_int &kern_recv, u_int &kern_drop);

private:
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    // timestamp of first received packet
    Timestamp _trace_start;

    // what channel the sniffer is "tuned to" (simulated)
    uint8_t _current_channel;

    int _dlt;
    int _limit;

    // simulated BPF
    u_int _ps_recv, _ps_drop;

    u_int _last_ps_recv;
    u_int _last_ps_drop;
    int32_t _total_count;
    int32_t _pkt_count;
    int32_t _delayed_count;
};

CLICK_ENDDECLS
#endif
