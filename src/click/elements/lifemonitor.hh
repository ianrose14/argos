#ifndef CLICK_LIFEMONITOR_HH
#define CLICK_LIFEMONITOR_HH
#include <click/element.hh>
#include <click/ewma.hh>
#include <click/hashmap.hh>
#include <click/ipaddress.hh>
#include <click/vector.hh>
#include <click/timer.hh>
#include <click/timestamp.hh>
CLICK_DECLS

/*
=c
LifeMonitor()
*/

#define LIFEMONITOR_MAGIC 0x090d3df4

class LifeMonitor : public Element {
public:
    LifeMonitor();
    ~LifeMonitor();

    const char *class_name() const	{ return "LifeMonitor"; }
    const char *port_count() const	{ return "0-1/0-1"; }
    const char *processing() const      { return PUSH; }
    const char *flow_code() const       { return "x/y"; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler *);
    int initialize(ErrorHandler *);
    void push(int, Packet*);
    void run_timer(Timer*);

private:
    struct ClientInfo {
        DirectEWMA avg_delay_ms;
        Timestamp last_recv;
        uint32_t counts;
        uint32_t drops;
        uint32_t last_seqnum;
    };

    static int counts_handler(int, String&, Element*, const Handler*, ErrorHandler*);
    static int drops_handler(int, String&, Element*, const Handler*, ErrorHandler*);
    static int last_ping_handler(int, String&, Element*, const Handler*, ErrorHandler*);
    static int latency_handler(int, String&, Element*, const Handler*, ErrorHandler*);
    static int reset_handler(const String&, Element*, void *, ErrorHandler*);

    Timer _timer;
    Timestamp _clock;
    Timestamp _send_interval;
    uint32_t _next_seqnum;
    bool _verbose;
    bool _error_chatter;
    HashMap<IPAddress, ClientInfo> _clients;
};

struct lifemonitor_msg {
    uint32_t magic_num;
    uint32_t seqnum;
};


CLICK_ENDDECLS
#endif
