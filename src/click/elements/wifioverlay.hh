#ifndef CLICK_WIFIOVERLAY_HH
#define CLICK_WIFIOVERLAY_HH
#include <click/element.hh>
#include <click/dequeue.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/packet_anno.hh>
#include "assoctracker.hh"
#include "loghandler.hh"
CLICK_DECLS

/*
=c

WifiOverlay()

*/

#define WIFI_CTL_FRAMELEN 10

class WifiOverlay : public Element {
public:
    WifiOverlay();
    ~WifiOverlay();

    const char *class_name() const	{ return "WifiOverlay"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PUSH; }

    // Element methods
    void add_handlers();
    void *cast(const char *);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet *);
    void run_timer(Timer *);

    inline IPAddress *lookup_mapping(EtherAddress &bssid) const { return _bss_mappings.findp(bssid); }

private:
    uint32_t assigned_bssids_count() const;
    void crunch_received_counts();
    String dump_routing_table() const;
    void process_counts(Packet*, const IPAddress*);
    void process_handler_request(Packet*);
    void process_routes(Packet*, const IPAddress*);
    void send_counts(const Timestamp*, const Timestamp*);
    int send_handler_write(const IPAddress*, const String*, const String*,
                           ErrorHandler*);
    void send_control_message(Packet*, const IPAddress*, uint16_t);
    void send_ping(const IPAddress*);
    void send_routes(const IPAddress*);

    static int query_handler(int, String&, Element*, const Handler*, ErrorHandler*);
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    struct PktCounter {
        PktCounter() : pkt_count(0), byte_count(0) {}
        PktCounter(uint32_t p, uint32_t b) : pkt_count(p), byte_count(b) {}
        void incr(uint32_t pkts, uint32_t bytes) { pkt_count += pkts; byte_count += bytes; }
        void incr(Packet *p) { pkt_count++; byte_count += p->length(); }
        void reset() { pkt_count = 0; byte_count = 0; }
        uint32_t pkt_count;
        uint32_t byte_count;
    };

    struct CountRecord {
        Timestamp duration;
        uint32_t pkt_count;
        uint32_t byte_count;
    };

    typedef HashMap<IPAddress, CountRecord> FullNetCounts;

    /****  Used only by the coordinator:  ****/

    HashMap<EtherAddress, FullNetCounts> _count_records;

    // initial waiting period before any routes can be created
    Timestamp _routes_warmup;
    Timestamp _routes_start;  // when routes can start being assigned
    Timestamp _routes_min_duration;
    bool _sticky_routes;
    HashMap<EtherAddress, int> _sticky_warnings;

    /****  Used by everyone:  ****/

    Timer _counts_timer;
    Timestamp _counts_interval;
    Timestamp _last_counts_time;

    bool _am_coordinator;
    IPAddress _coordinator_ip;
    IPAddress _local_ip;  // used only in 'assigned_bssids' handler

    // for the current interval, counts of frames/bytes received for each BSSID
    HashMap<EtherAddress, PktCounter> _bss_counts;

    // used to track client->BSSID associations
    const AssocTracker *_assoc_tracker;

    // mappings of BSSIDs to sniffers, used to route packets
    HashMap<EtherAddress, IPAddress> _bss_mappings;

    // collection of packet-queues, indexed by BSSID (for packets that we don't
    // yet know where to send)
    HashMap<EtherAddress, DEQueue<Packet*> > _wait_queues;
    uint32_t _wait_queues_total;
    uint32_t _wait_queue_capac;  // max length PER wait-queue

    // whenever routes are received from the coordinator, any BSSIDs that are
    // still unrouted get 1 "point" in this hashmap; if a BSSID ever gets 3
    // points, we print a warning
    HashMap<EtherAddress, int> _unrouted_count;

    bool _log_detailed_counts;
    Logger *_log;
};

// values for the subtype field of argos_ctrl annotations (the type field should
// be ARGOS_CTRL_ANNO_OVERLAY_TYPE)
enum {
    ARGOS_OVERLAY_SUBTYPE_COUNTS=1,
    ARGOS_OVERLAY_SUBTYPE_ROUTES=2,
    ARGOS_OVERLAY_SUBTYPE_PING=3,
    ARGOS_OVERLAY_SUBTYPE_SEIZECROWN=4,  // no longer used
    ARGOS_OVERLAY_SUBTYPE_HANDLER=5
};

struct argos_overlay_countset {
    uint32_t time_sec;
    uint32_t time_usec;
    uint32_t duration_msec;
    uint32_t elts;
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct argos_overlay_count {
    u_char bssid[6];
    u_char unused_space[2];
    uint32_t pkt_count;
    uint32_t byte_count;
} CLICK_SIZE_PACKED_ATTRIBUTE;

#define ARGOS_OVERLAY_MAX_HANDLER_NAMELEN 128
#define ARGOS_OVERLAY_MAX_HANDLER_ARGSLEN 128

struct argos_overlay_handler_write {
    char handler_name[ARGOS_OVERLAY_MAX_HANDLER_NAMELEN];  // handler name length capped
    char args[ARGOS_OVERLAY_MAX_HANDLER_ARGSLEN];  // args length capped
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct argos_overlay_routeset {
    uint32_t route_count;
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct argos_overlay_route {
    u_char bssid[6];
    char unused_space[2];
    uint32_t peer_ip;
} CLICK_SIZE_PACKED_ATTRIBUTE;

CLICK_ENDDECLS
#endif
