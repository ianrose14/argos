#ifndef CLICK_WEBREQUESTTRACKER_HH
#define CLICK_WEBREQUESTTRACKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/glue.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/ipflowid.hh>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS


#define ARGOS_WEBREQ_MSG_MAGIC 0x23cd98ff

// flag values to denote what was captured from a request/response flow-pair
// **these must match database values!**
#define ARGOS_WEBREQ_F_REQUEST    0x01  /* >0 packets from request stream */
#define ARGOS_WEBREQ_F_RESPONSE   0x02  /* >0 packets from response stream */
#define ARGOS_WEBREQ_F_REQSYN     0x04  /* request stream's SYN */
#define ARGOS_WEBREQ_F_REQHEAD    0x08  /* request stream's first data segment */
#define ARGOS_WEBREQ_F_HTTPHOST   0x10  /* value of http Host header */
#define ARGOS_WEBREQ_F_COOKIEDOM  0x20  /* domain from http Set-Cookie header */

class WebRequestTracker;

class TCPFlowInfo {
public:
    TCPFlowInfo();
    TCPFlowInfo(EtherAddress &, Timestamp &);
    ~TCPFlowInfo();

    // current impl: never signal early completion so we can make sure to get
    // all of the search strings
    inline bool is_complete() const { return false; }
    inline size_t mem_size() const {
        return sizeof(TCPFlowInfo)
            + (_http_host ? strlen(_http_host) : 0)
            + (_cookie_domain ? strlen(_cookie_domain) : 0)
            + _search_queries_alloc;
    }
    void terminate();

private:
    // multiple sniffers can cooperate to capture a single TCP flow, but it would
    // be annoying to keep track of all of them so we just save the ID of the
    // sniffer that captures the first packet (of the request stream, if
    // captured)
    int32_t _sniffer_id;
    EtherAddress _src_mac;
    Timestamp _min_ts, _max_ts;
    bool _has_syn, _has_data;
    uint32_t _syn_seq, _min_data_seq;
    uint8_t _flags;
    char *_http_host, *_cookie_domain, *_search_queries;
    size_t _search_queries_alloc;  // we usually overallocate

    // if true, then we are "done" with this flow and nothing more will be
    // processed other than timestamps - this way we can keep track of how long
    // the flow lasts so that we don't accidently think that a new flow (with
    // the same 5-tuple) has begun simply because we got another packet from
    // this flow
    bool _terminated;

    friend class WebRequestTracker;
};

class WebRequestTracker : public Element {
public:
    WebRequestTracker();
    ~WebRequestTracker();

    const char *class_name() const	{ return "WebRequestTracker"; }
    const char *port_count() const	{ return "1-2/0-2"; }
    const char *processing() const	{ return PUSH; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet*);
    void run_timer(Timer*);

    void shed_memory();
    int timeout_all_sessions();

private:
    void db_insert(int32_t, const Timestamp&, const EtherAddress&,
        const IPAddress&, uint16_t, uint8_t, const char*, const char*, const char*);
    bool get_mac_addrs(const Packet*, EtherAddress*, EtherAddress*);
    struct http_request *http_parse(Packet *);
    void process_packet(IPFlowID*, TCPFlowInfo*, Packet*, bool);
    void send_message(const IPFlowID&, const TCPFlowInfo&);
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    bool _am_server;
    int32_t _node_id;
    Timer _timer;
    Timestamp _interval;
    Timestamp _timeout;
    int _dlt;
    int32_t _mem_used;  // signed to detect underflow
    uint32_t _mem_high_thresh;

    // mapping from flow identifier to tcp flow info
    HashMap<IPFlowID, TCPFlowInfo> _sessions;

    PostgreSQL *_db;
    Logger *_log;
};

struct argos_userweb_msg {
    uint32_t magic;
    uint32_t node_id;
    uint8_t  src_mac[6];
    uint16_t dst_port;
    uint32_t dst_ip;
    uint8_t  flags;
    uint8_t  padding[3];
    uint32_t first_pkt_sec, first_pkt_usec;
    uint32_t last_pkt_sec, last_pkt_usec;
    char     http_host[256];
    char     cookie_domain[256];
    char     search_queries[];  // space allocated after struct
} CLICK_SIZE_PACKED_ATTRIBUTE;

CLICK_ENDDECLS
#endif
