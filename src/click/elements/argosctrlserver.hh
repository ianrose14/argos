#ifndef CLICK_ARGOSCTRLSERVER_HH
#define CLICK_ARGOSCTRLSERVER_HH
#include <click/element.hh>
#include <click/hashmap.hh> 
#include <click/string.hh>
#include <click/task.hh>
#include "buffer.h"
#include "loghandler.hh"
#include "argos/net_proto.h"
CLICK_DECLS

/*
=c

ArgosCtrlServer(PORTNUMBER [, I<KEYWORDS>])

=s comm

A connection manager (user-level)

=d

Keyword arguments are:

=over 8

=item PORT

TCP port to listen on.

=item LOGGING

debug, info, warn, error, or crit.

=item LOGGING

Log level.  How much to chatter.

=back

*/

class ArgosConnection;  // forward declaration

class ArgosCtrlServer : public Element {
public:
    ArgosCtrlServer();
    ~ArgosCtrlServer();

    const char *class_name() const	{ return "ArgosCtrlServer"; }
    const char *port_count() const	{ return PORTS_0_0; }

    void add_handlers();
    void cleanup(CleanupStage);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    bool run_task(Task*);
    void selected(int);

private:
    void close_fd(int fd);
    void delete_connection(ArgosConnection *conn);
    int disconnect_handler(const String&, ErrorHandler*);
    int disconnect_all_handler(const String&, ErrorHandler*);
    int initialize_socket_error(ErrorHandler *errh, const char *syscall);

    static String read_handler(Element*, void *);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    int _portno;              // port to listen on
    int _svrsock;             // file descriptor to listening socket
    Task _task;               // task to start listening for connections
    struct sockaddr_in _addr; // local (bound) address

    // maps from socket file descriptors to connection objects, and from IP
    // addresses to connection objects
    HashMap<int, ArgosConnection*> _fd_hash;

    // if non-empty, then only connections from these IPAddresses will be
    // handled normally
    Vector<IPAddress> _allowed_ips;

    // additional denied IPs
    Vector<IPAddress> _denied_ips;

    // pre-populated start-click command ready to be sent to clients upon
    // connecting
    struct argos_net_startclick_msg *_start_click_msg;
    size_t _start_click_msg_len;

    Logger *_log;

    friend class ArgosConnection;
};

class ArgosConnection {
public:
    ArgosConnection(int, const struct sockaddr_in*, ArgosCtrlServer*,
        uint32_t inbuflen=(ARGOS_NET_MAX_PKT_LEN+ARGOS_NET_MAX_COMPRESS_LEN),
        uint32_t outbuflen=(5*1024*1024));

    ~ArgosConnection();

    inline const IPAddress &address() const { return _addr; }
    inline const Timestamp &connect_time() const { return _connect_time; }
    inline int enqueue_cmd(const u_char *data, size_t len);
    inline int fd() const { return _fd; }
    inline bool finished() const { return _finished; }
    inline const String &name() const { return _name; }
    inline bool readable() const { return _selection & Element::SELECT_READ; }
    inline const IPAddress &socket_addr() const { return _sock_addr; }
    void socket_recv();
    void socket_send();
    int send_disconnect();
    inline bool writable() const { return _selection & Element::SELECT_WRITE; }

private:
    void process_inbuf();
    void protocol_error(uint8_t, const char *, ...);
    int send_error(uint8_t, const char *, ...);

    ArgosCtrlServer *_parent;
    IPAddress _addr;  // IP advertised in handshake message
    IPAddress _sock_addr;  // actual IP used in connection
    String _name;
    Timestamp _connect_time;
    int _fd;
    int _selection;   // what (read and/or write) this fd is selecting for
    bool _finished;   // connection is finished (socket should be closed)
    bool _handshook;  // whether a valid handshake has been received
    bool _invalid;    // protocol error occurred, invalidating the conn
    struct buffer *_inbuf;
    struct buffer *_outbuf;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
