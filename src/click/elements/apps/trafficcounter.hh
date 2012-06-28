#ifndef CLICK_TRAFFICCOUNTER_HH
#define CLICK_TRAFFICCOUNTER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS


#define TRAFFICCOUNTER_MAGIC 0x9328ee39

/*
=c
TrafficCounter()

*/

class TrafficCounter : public Element {
public:
    TrafficCounter();
    ~TrafficCounter();

    const char *class_name() const	{ return "TrafficCounter"; }
    const char *port_count() const	{ return "1/0-2"; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void run_timer(Timer*);
    Packet *simple_action(Packet *);

private:
    void db_insert(uint8_t, uint32_t, uint32_t, int32_t, bool, uint32_t,
        uint32_t, uint64_t, uint64_t);
    bool parse_port_pair(String&, uint16_t*, uint16_t*);
    String traffic_class_desc(uint8_t);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    enum TrafficClass {
        TRAFFIC_CLASS_ETHER = 1,
        TRAFFIC_CLASS_WIFI,
        TRAFFIC_CLASS_IP,
        TRAFFIC_CLASS_TCP,
        TRAFFIC_CLASS_UDP
    };

    class PktCounter {
    public:
        PktCounter() : pkt_count(0), byte_count(0) {}
        PktCounter(uint64_t p, uint64_t b) : pkt_count(p), byte_count(b) {}
        void incr(uint64_t pkts, uint64_t bytes) { pkt_count += pkts; byte_count += bytes; }
        void incr(Packet *p) { pkt_count++; byte_count += p->length(); }
        void reset() { pkt_count = 0; byte_count = 0; }
        uint64_t pkt_count;
        uint64_t byte_count;
    };

    bool _am_server;
    int32_t _node_id;
    bool _merged;
    Timer _timer;
    Timestamp _interval;
    Timestamp _interval_start;

    int _dlt;
    bool _ether_enabled, _wifi_enabled, _ip_enabled, _tcp_enabled, _udp_enabled;

    // traffic-class-specific counters:
    HashMap<uint16_t, PktCounter> _ether_counts;
    PktCounter _wifi_counts[64];
    HashMap<uint8_t, PktCounter> _ip_counts;
    Vector<PktCounter> _tcp_counts;
    Vector<uint16_t> _tcp_low_ports;
    Vector<uint16_t> _tcp_high_ports;
    Vector<PktCounter> _udp_counts;
    Vector<uint16_t> _udp_low_ports;
    Vector<uint16_t> _udp_high_ports;

    PostgreSQL *_db;
    Logger *_log;
};

struct argos_trafficcount_header {
    uint32_t magic;
    uint32_t node_id;
    uint8_t  is_merged;
    uint8_t  traffic_class;
    uint8_t  padding[2];
    uint32_t ts_sec;
    uint32_t duration_sec;
    uint32_t num_records;
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct argos_trafficcount_record {
    uint32_t type;
    uint32_t subtype;  // not used by all traffic classes
    uint64_t packets;
    uint64_t bytes;
} CLICK_SIZE_PACKED_ATTRIBUTE;

CLICK_ENDDECLS
#endif
