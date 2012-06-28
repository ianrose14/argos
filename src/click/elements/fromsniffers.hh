#ifndef CLICK_FROMSNIFFERS_HH
#define CLICK_FROMSNIFFERS_HH
#include <click/dequeue.hh>
#include <click/element.hh>
#include <click/ewma.hh>
#include <click/hashmap.hh> 
#include <click/string.hh>
#include <click/task.hh>
#include "buffer.h"
#include "loghandler.hh"
#include "quicklz.h"
#include "argos/net_proto.h"
#include "lzo/lzo1x.h"
CLICK_DECLS

/*
=c

FromSniffers(PORTNUMBER [, I<KEYWORDS>])

=s comm

A connection manager (user-level)

=d

Keyword arguments are:

=over 8

=item DLT

Name of datalink type expected from sniffers.

=item PORT

TCP port to listen on.

=item HEADROOM

Bytes of headroom to add to output packets.

=item LOGGING

debug, info, warn, error, or crit

=item NODELAY

Boolean.  If set, disable the Nagle algorithm on connected sockets. This means
that segments are always sent as soon as possible, even if there is only a small
amount of data. When not set, data is buffered until there is a sufficient
amount to send out, thereby avoiding the frequent sending of small packets,
which results in poor utilization of the network. Default is true.

=item LOGGING

Log level.  How much to chatter.

=back

*/

// what packets go to what ports
enum {
    FROMSNIFFERS_PORT_PCAP      = 0,
    FROMSNIFFERS_PORT_STATS     = 1,
    FROMSNIFFERS_PORT_PING      = 2,
    FROMSNIFFERS_PORT_HANDSHAKE = 3,
    FROMSNIFFERS_PORT_BADMSG    = 4
};

class FromSniffers : public Element {
public:
    FromSniffers();
    ~FromSniffers();

    const char *class_name() const	{ return "FromSniffers"; }
    const char *port_count() const	{ return "0/1-5"; }
    const char *processing() const	{ return PUSH; }

    void add_handlers();
    void cleanup(CleanupStage);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    bool run_task(Task*);
    void selected(int);
    static int static_initialize(ErrorHandler*);

protected:
    typedef DEQueue<String> CmdList;

    int add_bpf_handler(const String&, ErrorHandler*);
    int disconnect_handler(const String&, ErrorHandler*);
    int disconnect_all_handler(const String&, ErrorHandler*);
    inline int dlt(void);
    int is_connected_handler(const String&, ErrorHandler*);
    static String read_handler(Element *, void *);
    int set_channel_handler(const String&, ErrorHandler*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    // variables accessible to Connection objects (inner class)
    Logger *_log;
    uint32_t _headroom;  // how much headroom to add when creating packets

private:
    class Connection;  // forward declaration

    void close_fd(int fd);
    void delete_connection(Connection *conn);
    Connection *get_conn_by_ip(IPAddress&);
    int initialize_socket_error(ErrorHandler *errh, const char *syscall);
    bool test_bpf_expr(String bpf_expr, ErrorHandler *errh);

    int _dlt;                 // connections MUST report this dlt
    int _portno;              // port to listen on
    bool _nodelay;            // disable Nagle algorithm
    int _svrsock;             // file descriptor to listening socket
    Task _task;               // task to start listening for connections
    struct sockaddr_in _addr; // local (bound) address

    // maps from socket file descriptors to connection objects, and from IP
    // addresses to connection objects
    HashMap<int, Connection*> _fd_hash;
    HashMap<IPAddress, int> _ip_hash;

    // This is just a record of all IPs who have every connected in the past;
    // its used so that sniffers can be sent a 'close-connection' message
    // immediately after they connect for the first time, forcing them to flush
    // their network buffers.  This prevents us from receiving crap (stats
    // messages and captured packets) from before this server instance was even
    // started (and thus, which we probably don't care about).
    HashMap<IPAddress, u_char> _client_history;

    // aggregated bpf filter
    String _agg_bpf_filter;
    int _agg_bpf_count;

    // fields for "Counter"-like handlers:
    typedef RateEWMAX<RateEWMAXParameters<4, 10, uint64_t, int64_t> > rate_t;
    typedef RateEWMAX<RateEWMAXParameters<4, 4, uint64_t, int64_t> > byte_rate_t;
    uint64_t _count;
    uint64_t _byte_count;
    rate_t _rate;
    byte_rate_t _byte_rate;


    //
    // *****  Connection class  *****
    //

    class Connection {
    public:
        Connection(int, const struct sockaddr_in*, FromSniffers *,
            uint32_t inbuflen=(ARGOS_NET_MAX_PKT_LEN+ARGOS_NET_MAX_COMPRESS_LEN),
            uint32_t pktbuflen=(ARGOS_NET_MAX_PKT_LEN+ARGOS_NET_MAX_COMPRESS_LEN));

        ~Connection();

        inline IPAddress address(void);
        inline const String &desc() const;
        inline void enqueue_cmd(const u_char *data, size_t len);
        inline int fd(void);
        inline bool finished(void);
        inline bool readable(void);
        void socket_recv(void);
        void socket_send(void);
        int send_disconnect(void);
        inline bool writable(void);

    private:
        bool decompress_packets(uint8_t, const u_char*, uint32_t, u_char*, uint32_t);
        void process_buffer(struct buffer*, int*, int*);
        void process_pktbuf(void);
        void protocol_error(uint8_t, const char *, ...);
        void send_bpf_filter(bool close=false);

        FromSniffers *_parent;
        IPAddress _address;
        String _desc;
        String _hostname;
        int _fd;
        int _selection;   // what (read and/or write) this fd is selecting for
        bool _finished;   // connection is finished (socket should be closed)
        bool _handshook;  // whether a valid handshake has been received
        bool _invalid;    // protocol error occurred, invalidating the conn
        struct buffer *_inbuf;
        struct buffer *_pktbuf;
        char qlz_scratch[QLZ_SCRATCH_DECOMPRESS];  // for QuickLZ decompressor
        CmdList _outq;    // list of commands to send
        int _sent;        // bytes sent so far (of command at head of _outq)
        Timestamp _last_recv;
        Logger *_log;
    };
};

CLICK_ENDDECLS
#endif
