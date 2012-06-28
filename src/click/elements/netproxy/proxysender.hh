#ifndef CLICK_PROXYSENDER_HH
#define CLICK_PROXYSENDER_HH
#include <click/element.hh>
#include <click/notifier.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../buffer.h"
#include "../loghandler.hh"
#include "../quicklz.h"
#include "../argos/net_proto.h"
CLICK_DECLS

/*
=c

ProxySender()

*/

/*
 * According to the QuickLZ manual, the maximum that a data buffer can expand
 * during compression is 400 bytes.
 * http://www.quicklz.com/manual.html
 */
#define QLZ_MAX_INFLATE 400

// due to circular dependencies, we can't #include proxyclient.hh in this file,
// so just make a forward declaration so that we can compile
class ProxyClient;

class ProxySender {
public:
    ProxySender(const struct sockaddr_in*, const struct sockaddr_in*, size_t,
        Element *, ProxyClient *client=NULL);
    ~ProxySender();

    inline uint32_t byte_count() const { return _bytes_sent; }
    int close();
    int initialize();
    inline bool is_connected() const { return _state == STATE_CONNECTED; }
    inline bool is_selecting() const { return _selecting; }
    inline uint32_t pkt_count() const { return _pkts_sent; }
    inline IPAddress peer() const { return IPAddress(_remote_addr.sin_addr); }
    inline void reset_counts() { _bytes_sent = 0; _pkts_sent = 0; }
    bool run_task(Task *);
    void run_timer(Timer *);
    void selected(int);
    inline void set_logger(Logger *log);
    inline void set_send_delay(Timestamp &delay) { _send_delay = delay; }
    inline void trace_performance(bool yes) { _trace_perf = yes; }

private:
    void add_select();
    void compress_databuf();
    static inline size_t get_serialized_len(const Packet *);
    void handle_connect();
    void handle_connect_failure();
    void handle_connect_success();
    void handle_writable();
    void remove_select();
    void reset_connection();
    void run_compress_timer();
    void run_connect_timer();
    static size_t serialize_packet(const Packet *, u_char *, size_t);

    enum { STATE_IDLE, STATE_CONNECTING, STATE_CONNECTED, STATE_BACKOFF, STATE_DEAD }
        _state;

    Timer _compress_timer;
    Timer _connect_timer;
    Task _task;

    int _sock;
    struct sockaddr_in _remote_addr;
    bool _has_local_addr;
    struct sockaddr_in _local_addr;
    Element *_elt;
    bool _selecting;
    ProxyClient *_client;
    u_int _cur_backoff;
    u_int _init_backoff;
    u_int _max_backoff;
    NotifierSignal *_signal;
    Timestamp _send_delay;
    Packet *_next_packet;
    struct buffer *_databuf;
    struct buffer *_sendbuf;
    char _qlz_scratch[QLZ_SCRATCH_COMPRESS];
    uint32_t _bytes_sent;
    uint32_t _pkts_sent;
    uint32_t _pkts_buffered;
    uint32_t _pkts_compressed;

    // to suppress repeated connection failure messages
    bool _suppress_connect_errors;

    bool _trace_perf;
    Logger *_log;
};

size_t
ProxySender::get_serialized_len(const Packet *p)
{
    // we assume that tailroom is garbage and does not need to be sent
    return p->length() + sizeof(struct argos_net_clickpkt_msg);
}

void
ProxySender::set_logger(Logger *l)
{
    char prefix[256];
    snprintf(prefix, sizeof(prefix), "[ProxySender %s] ", inet_ntoa(_remote_addr.sin_addr));
    _log = l->clone(prefix);
}

CLICK_ENDDECLS
#endif
