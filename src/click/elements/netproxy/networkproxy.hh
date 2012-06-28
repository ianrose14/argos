#ifndef CLICK_NETWORKPROXY_HH
#define CLICK_NETWORKPROXY_HH
#include <click/element.hh>
#include <click/dequeue.hh>
#include <click/notifier.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include "../buffer.h"
#include "../quicklz.h"
#include "../loghandler.hh"
#include "../argos/net_proto.h"
CLICK_DECLS

/*
=c

NetworkProxy()

*/

// enable debugging/safety checks?  (for now, enable IFF QLZ_MEMORY_SAFE is
// enabled in quicklz.h since they will probably go hand in hand)
#ifdef QLZ_MEMORY_SAFE
#define ARGOS_NETPROXY_SAFE
#endif

class NetworkProxy : public Element {
public:
    NetworkProxy();
    ~NetworkProxy();

    const char *class_name() const	{ return "NetworkProxy"; }
    const char *port_count() const	{ return PORTS_1_0; }
    const char *processing() const      { return PULL; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    inline IPAddress dst_ip() const { return IPAddress(_remote_addr.sin_addr); }
    inline uint16_t dst_port() const { return ntohs(_remote_addr.sin_port); }
    int initialize(ErrorHandler*);
    bool run_task(Task*);
    void run_timer(Timer*);
    void selected(int);
    int set_destination(const String&, uint16_t, ErrorHandler *);
    
private:
    static inline size_t get_serialized_len(const Packet *);
    static size_t serialize_packet(const Packet *, u_char *, size_t);
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    int close();
    void handle_connect();
    void handle_connect_failure();
    void handle_connect_success();
    void handle_writable();
    void process_recv_buffer();
    bool pull_inputs();
    void reset_connection();
    void run_compress_timer();
    void run_connect_timer();
    bool try_compress_databuf();

    enum proxyState {
        STATE_IDLE,         // not yet started up
        STATE_CONNECTING,   // waiting for the results of a connect() call
        STATE_BACKOFF,      // pausing before another connect() attempt
        STATE_CONNECTED,    // sending data or waiting for data to send
        STATE_DEAD,         // closed (entire element, not just the socket)
    } _state;

    // used to wait until its time to compress the databuf into the sendbuf
    Timer _compress_timer;

    // used to wait until its time to make another connection attempt
    Timer _connect_timer;

    // used to pull packets from upstream elements
    Task _task;

    bool _has_local_addr;
    bool _bind_local_addr;
    struct sockaddr_in _local_addr;
    struct sockaddr_in _remote_addr;

    int _sock;
    u_int _cur_backoff;
    u_int _init_backoff;
    u_int _max_backoff;

    // when a packet is received, it is not compressed (and sent) immediately to
    // allow (a little) time for additional packets to arrive to be handled
    // together (which is more efficient and saves b/w)
    Timestamp _send_delay;
    NotifierSignal _signal;
    Packet *_p;
    int32_t _burst;

    // Packets are first written to the end of the databuf.  Eventually
    // (e.g. when its full), a new NetworkBuffer is created to hold the
    // databuf's contents after they are compressed.  The NetworkBuffer's
    // contents are sent over the socket; once this is complete its appended to
    // _pending_bufs which is a list of sent buffers waiting for ACKs so that
    // they can be released.
    uint32_t _min_compress_len;  // avoids inefficient compressions
    struct buffer *_databuf;
    struct buffer *_sendbuf;
    bool _sendbuf_aligned;  // whether sendbuf starts with a complete msg (vs partial)
    uint32_t _pkts_buffered;
    uint32_t _pkts_compressed;
    char _qlz_scratch[QLZ_SCRATCH_COMPRESS];

    uint32_t _bytes_sent;  // number of bytes sent to the socket
    uint32_t _pkts_sent;   // number of packets sent to the socket

    uint64_t _total_compress_in;   // bytes
    uint64_t _total_compress_out;  // bytes
    uint64_t _compressions_count;  // number of compressions performed

    Timestamp _total_cpu_time;
    Timestamp _start_cpu_time;

    bool _suppress_connect_errors;  // used to avoid spamming the log
    bool _trace_cpu;
    Logger *_log;
};

size_t
NetworkProxy::get_serialized_len(const Packet *p)
{
    // we assume that tailroom is garbage and does not need to be sent
    return p->length() + sizeof(struct argos_net_clickpkt_msg);
}

CLICK_ENDDECLS
#endif
