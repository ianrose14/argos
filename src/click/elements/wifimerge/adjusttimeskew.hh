#ifndef CLICK_ADJUSTTIMESKEW_HH
#define CLICK_ADJUSTTIMESKEW_HH
#include <clicknet/wifi.h>
#include <click/dequeue.hh>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/packet.hh>
#include <click/pair.hh>
#include <click/timestamp.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
AdjustTimeSkew()

=s Argos

=d

Copies the packet's timestamp anno to the FIRST_TIMESTAMP anno slot.  Adjusts
the packet's timestamp up or down according to the estimated time skew between
the node that captured that packet (as recorded in the ARGOS_SNIFF_ANNO slot)
and some "baseline" node.  Also tries to estimate the accuracy of the time
estimate, putting it (expressed in microseconds) in the TIMESKEW_ERR anno slot.

*/

class AdjustTimeSkew : public Element {
public:
    AdjustTimeSkew();
    ~AdjustTimeSkew();

    const char *class_name() const	{ return "AdjustTimeSkew"; }
    const char *port_count() const	{ return "2/2"; }
    const char *processing() const      { return PUSH; }
    const char *flow_code () const      { return "#/#"; }
    const char *flags() const           { return "S0"; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    void push(int, Packet*);

private:
    static String read_handler(Element *, void *);
    void add_skew_measurement(IPAddress&, IPAddress&, Timestamp);
    bool estimate_timeskew(IPAddress&, Timestamp*, Timestamp*) const;
    static Timestamp get_median(const DEQueue<Timestamp>*);
    Timestamp get_spread(const DEQueue<Timestamp>*) const;

    Timestamp _end_warmup;
    Timestamp _warmup_dur;
    IPAddress _base_ip;

    // used to decide which IP should be the 'base' IP
    HashMap<IPAddress, uint32_t> _counts;

    struct IPAndSkew {
        IPAndSkew(const IPAddress &_ip) {
            ip = _ip;
            skews = DEQueue<Timestamp>();
        }

        IPAddress ip;
        DEQueue<Timestamp> skews;  // recent timeskew estimates
    };

    typedef Vector<IPAndSkew> TimeSkewList;

    // map of source IP to list of dest-IPs (with dest-IP timeskew estimates)
    typedef HashMap<IPAddress, TimeSkewList> TimeSkewMap;

    TimeSkewMap _skew_map;
    int _winsize;
    Timestamp *_workspace;

    Logger *_log;
};

CLICK_ENDDECLS
#endif
