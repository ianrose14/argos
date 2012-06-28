/*
 * fromsniffers.{cc,hh} -- receives argos messages from remote sniffers and
 *     sends commands to them
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "fromsniffers.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/packet_anno.hh>
#include <click/packet.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pcap/pcap.h>
#include "argos/common.h"
#include "argos/anno.h"
#include "argos/net_proto.h"
#include "argos/version.h"
CLICK_DECLS

#define die(msg)                                    \
    do {                                            \
        click_chatter(msg);                         \
        exit(1);                                    \
    } while (0)


// *************************************
// FromSniffers class methods
// *************************************

FromSniffers::FromSniffers()
    : _log(NULL), _headroom(Packet::default_headroom), _dlt(-1),
      _portno(ARGOS_NET_DEF_SERVER_PORT), _nodelay(true), _svrsock(-1),
      _task(this), _count(0), _byte_count(0)
{
}

FromSniffers::~FromSniffers()
{
    if (_log != NULL) delete _log;
}

enum { H_ADD_BPF, H_DISCONNECT, H_DISCONNECT_ALL, H_IS_CONNECTED, H_SET_CHANNEL,
       H_COUNT, H_BYTE_COUNT, H_RATE, H_BIT_RATE, H_BYTE_RATE, H_RESET };

void
FromSniffers::add_handlers()
{
    // 'is_connected' is (semantically) a read handler masquerading as a write
    // handler (because you can't pass arguments to read handers)
    add_write_handler("add_bpf", write_handler, (void*)H_ADD_BPF);
    add_write_handler("disconnect", write_handler, (void*)H_DISCONNECT);
    add_write_handler("disconnect_all", write_handler, (void*)H_DISCONNECT_ALL);
    add_write_handler("is_connected", write_handler, (void*)H_IS_CONNECTED);
    add_write_handler("set_channel", write_handler, (void*)H_SET_CHANNEL);
    add_task_handlers(&_task);

    // "Counter"-like handlers
    add_read_handler("count", read_handler, (void *)H_COUNT);
    add_read_handler("byte_count", read_handler, (void *)H_BYTE_COUNT);
    add_read_handler("rate", read_handler, (void *)H_RATE);
    add_read_handler("bit_rate", read_handler, (void *)H_BIT_RATE);
    add_read_handler("byte_rate", read_handler, (void *)H_BYTE_RATE);
    add_write_handler("reset", write_handler, (void *)H_RESET);
    add_write_handler("reset_counts", write_handler, (void *)H_RESET);
}

void
FromSniffers::cleanup(CleanupStage)
{
    // close listening socket
    int res;
    if (_svrsock != -1) {
        res = shutdown(_svrsock, SHUT_RDWR);
        if (res != 0)
            _log->strerror("shutdown() on server socket %d", _svrsock);

        close_fd(_svrsock);
        _svrsock = -1;
    }

    // clean up all open connections (is there a better way to do this?)
    while (1) {
        HashMap<int, Connection*>::iterator iter = _fd_hash.begin();
        if (!iter.live()) break;
        Connection *conn = iter.value();
        int fd = iter.pair()->key;
        _fd_hash.erase(fd);
        
        delete conn;
        close_fd(fd);
    }
}

int
FromSniffers::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dltname;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "DLT", cpkM, cpString, &dltname,
            "PORT", 0, cpTCPPort, &_portno,
            "HEADROOM", 0, cpUnsigned, &_headroom,
            "NODELAY", 0, cpUnsigned, &_nodelay,
            "LOGGING", 0, cpString, &loglevel,
            "NETLOG", 0, cpString, &netlog,
            "LOGGER", 0, cpString, &logelt,
            cpEnd) < 0)
        return -1;

    // create log before anything else
    _log = LogHandler::get_logger(this, NULL, loglevel.c_str(), netlog.c_str(),
        logelt.c_str(), errh);
    if (_log == NULL)
        return -EINVAL;

    _dlt = pcap_datalink_name_to_val(dltname.c_str());
    if (_dlt == -1)
        return errh->error("invalid DLT value");

    return 0;
}

int
FromSniffers::initialize(ErrorHandler *errh)
{
    // always call static_initialize in case we are the first instance created
    int rv = static_initialize(errh);
    if (rv != 0) return rv;

    _log->info("Initializing.  Argos version %d.%02d  (built %s %s)",
        ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION, __DATE__, __TIME__);

    // open socket, set options
    _svrsock = socket(AF_INET, SOCK_STREAM, 0);
    if (_svrsock < 0)
        return initialize_socket_error(errh, "socket");

#ifdef TCP_NODELAY
    // disable Nagle algorithm
    if (_nodelay)
        if (setsockopt(_svrsock, IP_PROTO_TCP, TCP_NODELAY, &_nodelay, sizeof(_nodelay)) < 0)
            return initialize_socket_error(errh, "setsockopt(TCP_NODELAY)");
#endif

    struct addrinfo hints, *servinfo;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char portstr[32];
    snprintf(portstr, sizeof(portstr), "%d", _portno);

    rv = getaddrinfo(NULL, portstr, &hints, &servinfo);
    if (rv != 0)
        return errh->error("getaddrinfo: %s", gai_strerror(rv));

    // if getaddrinfo returns 0, it should return a list of addrinfo structs
    assert(servinfo != NULL);
    assert(servinfo->ai_addrlen <= sizeof(struct sockaddr_in));

    if (bind(_svrsock, servinfo->ai_addr, servinfo->ai_addrlen) < 0) {
        freeaddrinfo(servinfo);
        return initialize_socket_error(errh, "bind");
    }

    memcpy(&_addr, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);

    ScheduleInfo::initialize_task(this, &_task, true, errh);
    return 0;
}

bool
FromSniffers::run_task(Task *)
{
    // start listening
    if (listen(_svrsock, 5) < 0) {
        (void) initialize_socket_error(NULL, "listen");
        return true;
    }

    // shouldn't be needed since we only call accept() when the fd has been
    // selected, but set it to be defensive in case click screws up
    if (fcntl(_svrsock, F_SETFL, O_NONBLOCK) == -1) {
        (void) initialize_socket_error(NULL, "fcntl(O_NONBLOCK)");
        // not treated as a fatal error
    }

    _log->info("listening for connections on %s:%d",
        inet_ntoa(_addr.sin_addr), ntohs(_addr.sin_port));

    add_select(_svrsock, SELECT_READ);  // select for accept()
    return true;
}

void
FromSniffers::selected(int fd)
{
    if (fd == _svrsock) {
        // accept new connections
        struct sockaddr_in addr;
        size_t addrlen = sizeof(addr);
        int sock = accept(_svrsock, (struct sockaddr*)&addr, &addrlen);

        if (sock < 0) {
            // note: treat EAGAIN and 'real' socket errors the same way
            _log->strerror("accept");
            return;
        }

        Connection *conn = new Connection(sock, &addr, this);

        // ensure that Connection creation was successful
        if (conn->finished()) {
            // something failed in Connection ctor
            delete conn;
            return;
        }

        _log->info("accepted connection from %s", conn->desc().c_str());

        // shouldn't be needed since we only call recv() and send() when the fd
        // has been selected, but set it to be defensive in case click screws up
        if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
            _log->strerror("fnctl(O_NONBLOCK)");
            close_fd(sock);
            return;
        }

        assert(_fd_hash.find(sock) == NULL);
        _fd_hash.insert(sock, conn);

        // If we get multiple (concurrent) connections from the same IP, this
        // causes problems for _ip_hash because it assumes there is a 1:1
        // mapping; as a simple workaround, we only store the first connection
        // in _ip_hash.  This means that the various write-handlers
        // exposed from this element may not work properly (i.e. they may do
        // nothing) if a connection closes while another connection to the same
        // IP is still open.
        if (_ip_hash.findp(conn->address()) == NULL)
            _ip_hash.insert(conn->address(), sock);
    } else {  // fd != _svrsock
        Connection *conn = _fd_hash.find(fd);
        if (conn == NULL) {
            // I don't know about this fd - this is an error
            _log->error("selected() called for unknown fd %d", fd);
            return;
        }

        // This is stupid; click tells me that this fd was selected, but not
        // what it was selected for!  So we have to keep track of it ourselves.
        if (conn->writable())
            conn->socket_send();

        // again, check if the connection was terminated and should be closed
        if (conn->finished()) {
            delete_connection(conn);
            return;
        }

        // if willing to receive, try to do so
        if (conn->readable())
            conn->socket_recv();

        // again, check if the connection was terminated and should be closed
        if (conn->finished()) {
            delete_connection(conn);
            return;
        }
    }
}

int
FromSniffers::static_initialize(ErrorHandler *errh)
{
    static int initialized = 0;
    if (initialized) return 0;

    // initialize the LZO library; this should be done only once
    if (lzo_init() == LZO_E_OK) {
        initialized = 1;
        return 0;
    } else {
        return errh->error("initialization of LZO library failed");
    }
}


/*
 * Protected Methods
 */

int
FromSniffers::add_bpf_handler(const String &s_in, ErrorHandler *errh)
{
    uint8_t priority;
    String name;
    String bpf_filter = "";

    if (cp_va_kparse(s_in, this, errh,
            "NAME", cpkP+cpkM, cpString, &name,
            "PRIORITY", cpkP+cpkM, cpByte, &priority,
            "BPF_FILTER", cpkP, cpString, &bpf_filter,
            cpEnd) < 0)
        return -EINVAL;

    _log->debug("new BPF filter from %s: \"%s\"", name.c_str(),
        bpf_filter.c_str());

    // this handler is special in that it can only be called during the
    // initialization phase; any later attempts will fail
    if (router()->initialized())
        return errh->error("cannot access add_bpf handler after initialization phase");

    String new_agg_filter = "";
    if (_agg_bpf_count == 0) {
        if (bpf_filter != "")
            new_agg_filter = "(" + bpf_filter + ")";
    } else {
        // semantically, "[empty string] or <anything>" is equivalent to
        // just "[empty string]" since the empty string captures everything
        if (_agg_bpf_filter != "") {
            if (bpf_filter != "") {
                new_agg_filter = _agg_bpf_filter + " or (" +
                    bpf_filter + ")";
            }
        } else {
            if (bpf_filter != "") {
                new_agg_filter = "(" + bpf_filter + ")";
            }
        }
    }

    if (new_agg_filter.length() > ARGOS_NET_MAX_BPF_LEN)
        return errh->error("length of aggregate filter (%u) exceeds protocol"
            " maximum (%u)", new_agg_filter.length(), ARGOS_NET_MAX_BPF_LEN);

    if (!test_bpf_expr(new_agg_filter, errh))
        return -EINVAL;

    _log->debug("aggregate BPF filter is now \"%s\"", new_agg_filter.c_str());

    _agg_bpf_filter = new_agg_filter;
    _agg_bpf_count++;
    return 0;
}

int
FromSniffers::disconnect_handler(const String &s_in, ErrorHandler *errh)
{
    IPAddress ip;
    if (cp_va_kparse(s_in, this, errh,
            "IP", cpkP+cpkM, cpIPAddress, &ip,
            cpEnd) < 0)
        return -EINVAL;

    Connection *conn = get_conn_by_ip(ip);
    if (conn == NULL) {
        _log->debug("write-handler request to disconnect %s (not connected)",
            ip.unparse().c_str());
        return -ENOTCONN;
    }

    _log->debug("write-handler request to disconnect %s", ip.unparse().c_str());
    if (conn->send_disconnect() != 0)
        return -errno;
    else
        return 0;
}

int
FromSniffers::disconnect_all_handler(const String &, ErrorHandler *)
{
    _log->debug("write-handler request to disconnect all clients");

    // stop accepting new connections
    remove_select(_svrsock, SELECT_READ);

    HashMap<int, Connection*>::iterator iter = _fd_hash.begin();
    for (; iter != _fd_hash.end(); iter++) {
        Connection *conn = iter.value();
        (void) conn->send_disconnect();
    }

    return 0;
}

inline int
FromSniffers::dlt()
{
    return _dlt;
}

int
FromSniffers::is_connected_handler(const String &s_in, ErrorHandler *errh)
{
    IPAddress ip;
    if (cp_va_kparse(s_in, this, errh,
            "IP", cpkP+cpkM, cpIPAddress, &ip,
            cpEnd) < 0)
        return -EINVAL;

    return (_ip_hash.findp(ip) != NULL);
}

String
FromSniffers::read_handler(Element *e, void *thunk)
{
    FromSniffers *elt = static_cast<FromSniffers *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_COUNT:
        return String(elt->_count);
    case H_BYTE_COUNT:
	return String(elt->_byte_count);
    case H_RATE:
        // I don't understand this next line; its copied from counter.cc
	elt->_rate.update(0);	// drop rate after idle period
	return elt->_rate.unparse_rate();
    case H_BIT_RATE:
        // I don't understand this next line; its copied from counter.cc
	elt->_byte_rate.update(0); // drop rate after idle period
	// avoid integer overflow by adjusting scale factor instead of
	// multiplying
	if (elt->_byte_rate.scale() >= 3)
	    return cp_unparse_real2(elt->_byte_rate.scaled_average() * elt->_byte_rate.epoch_frequency(), elt->_byte_rate.scale() - 3);
	else
	    return cp_unparse_real2(elt->_byte_rate.scaled_average() * elt->_byte_rate.epoch_frequency() * 8, elt->_byte_rate.scale());
    case H_BYTE_RATE:
        // I don't understand this next line; its copied from counter.cc
        elt->_byte_rate.update(0); // drop rate after idle period
	return elt->_byte_rate.unparse_rate();
    default:
        return "internal error (bad thunk value)";
    }
}

int
FromSniffers::set_channel_handler(const String &s_in, ErrorHandler *errh)
{
    IPAddress ip;
    uint16_t channel;

    if (cp_va_kparse(s_in, this, errh,
            "IP", cpkP+cpkM, cpIPAddress, &ip,
            "CHANNEL", cpkP+cpkM, cpUnsignedShort, &channel,
            cpEnd) < 0)
        return -EINVAL;

    Connection *conn = get_conn_by_ip(ip);
    if (conn == NULL) {
        return -ENOTCONN;  // sniffer is not connected currently
    }

    _log->debug("set-channel command: %s to chan %hu", ip.s().c_str(), channel);

    size_t reqlen = sizeof(struct argos_net_setchan_msg);
    struct argos_net_setchan_msg *msg = (struct argos_net_setchan_msg*)
        malloc(reqlen);
    if (msg == NULL) die("malloc failure");

    msg->msgtype = htons(ARGOS_NET_SETCHAN_MSGTYPE);
    msg->msglen = htonl(reqlen);
    msg->chan = htons(channel);

    conn->enqueue_cmd((u_char*)msg, reqlen);
    return 0;
}

int
FromSniffers::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    FromSniffers *elt = static_cast<FromSniffers *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_ADD_BPF:
        return elt->add_bpf_handler(s_in, errh);
    case H_DISCONNECT:
        return elt->disconnect_handler(s_in, errh);
    case H_DISCONNECT_ALL:
        return elt->disconnect_all_handler(s_in, errh);
    case H_IS_CONNECTED:
        return elt->is_connected_handler(s_in, errh);
    case H_SET_CHANNEL:
        return elt->set_channel_handler(s_in, errh);
    case H_RESET:
        elt->_count = 0;
        elt->_byte_count = 0;
        return 0;
    default:
        return errh->error("internal error (bad thunk value)");
    }
}


/*
 * Private Methods
 */

void
FromSniffers::close_fd(int fd)
{
    do {
        int rv = close(fd);
        if (rv == 0) break;
        if (errno != EINTR) {
            _log->strerror("close() on socket %d", fd);
            break;
        }
        // else, errno == EINTR, and we loop
    } while (1);
}

void
FromSniffers::delete_connection(Connection *conn)
{
    remove_select(conn->fd(), SELECT_READ | SELECT_WRITE);

    int removed = _fd_hash.erase(conn->fd());
    assert(removed == 1);

    // its possible that _ip_hash does not have an entry for this IP; see
    // earlier comments regarding concurrent connections from the same IP in
    // FromSniffers::selected()
    removed = _ip_hash.erase(conn->address());

    close_fd(conn->fd());
    delete conn;
}

FromSniffers::Connection*
FromSniffers::get_conn_by_ip(IPAddress &ip)
{
    int *fd_ptr = _ip_hash.findp(ip);
    if (fd_ptr == NULL) return NULL;

    Connection *conn = _fd_hash.find(*fd_ptr);
    if (conn == NULL) {
        _log->critical("_fd_hash and _ip_hash out of sync");
        return NULL;
    }
    return conn;
}

int
FromSniffers::initialize_socket_error(ErrorHandler *errh, const char *syscall)
{
    int e = errno;		// preserve errno

    if (_svrsock >= 0) {
        remove_select(_svrsock, SELECT_READ | SELECT_WRITE);
        close_fd(_svrsock);
        _svrsock = -1;
    }

    if (errh != NULL) {
        return errh->error("%s: %s", syscall, strerror(e));
    } else {
        _log->error("%s: %s", syscall, strerror(e));
        return -1;
    }
}

bool
FromSniffers::test_bpf_expr(String bpf_expr, ErrorHandler *errh)
{
    int snaplen = 128;  // doesn't matter; no packets are actually read
    pcap_t *pcap_h = pcap_open_dead(_dlt, snaplen);
    if (pcap_h == NULL) return errh->error("pcap_open_dead: %s", strerror(errno));

    struct bpf_program bpf;
    if (pcap_compile(pcap_h, &bpf, bpf_expr.c_str(), 1 /* optimize */, 0) == -1) {
        errh->error("pcap_compile failed for DLT_%s: %s",
            pcap_datalink_val_to_name(_dlt), pcap_geterr(pcap_h));
        pcap_close(pcap_h);
        return false;
    }

    pcap_freecode(&bpf);
    pcap_close(pcap_h);
    return true;
}


// *************************************
// Connection class methods
// *************************************

FromSniffers::Connection::Connection(int fd, const struct sockaddr_in *addr,
    FromSniffers *parent, uint32_t inbuflen, uint32_t pktbuflen)
{
    _parent = parent;
    _address = IPAddress(addr->sin_addr);
    _fd = fd;
    _finished = false;
    _handshook = false;
    _invalid = false;
    _sent = 0;
    _log = _parent->_log;

    _inbuf = buffer_create(inbuflen);
    if (_inbuf == NULL) {
        // malloc failed - terminate right away
        _log->debug("buffer_create(%d) failed in Connection ctor", inbuflen);
        _finished = true;
        return;
    }

    _pktbuf = buffer_create(pktbuflen);
    if (_pktbuf == NULL) {
        // malloc failed - terminate right away
        _log->debug("buffer_create(%d) failed in Connection ctor", pktbuflen);
        _finished = true;
        return;
    }

    char hostname[NI_MAXHOST];
    int rv = getnameinfo((const struct sockaddr*)addr, sizeof(struct sockaddr),
        hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);

    if (rv == 0) {
        for (size_t i=0; i < strlen(hostname); i++) {
            if (hostname[i] == '.') {
                hostname[i] = '\0';
                break;
            }
        }
        if (strlen(hostname) == 0)
            _hostname = "?";
        else
            _hostname = String(hostname);

        _desc = _address.s() + " (" + _hostname + ")";
    } else {
        if (rv != EAI_NONAME)
            _log->error("getnameinfo: %s", gai_strerror(rv));
        _hostname = _address.s();
        _desc = _hostname;
    }

    // only select for readability right now (since there is no data to send)
    _parent->add_select(fd, SELECT_READ);
    _selection = SELECT_READ;
}

FromSniffers::Connection::~Connection()
{
    _outq.clear();
    if (_inbuf != NULL) buffer_destroy(_inbuf);
    if (_pktbuf != NULL) buffer_destroy(_pktbuf);
}

inline IPAddress
FromSniffers::Connection::address()
{
    return _address;
}

inline const String &
FromSniffers::Connection::desc() const
{
    return _desc;
}

inline void
FromSniffers::Connection::enqueue_cmd(const u_char *data, size_t len)
{
    _outq.push_back(String((const char*)data, len));

    if ((_selection & SELECT_WRITE) == 0) {
        _selection |= SELECT_WRITE;
        _parent->add_select(_fd, SELECT_WRITE);
    }
}

inline int
FromSniffers::Connection::fd()
{
    return _fd;
}

inline bool
FromSniffers::Connection::finished()
{
    return _finished;
}

inline bool
FromSniffers::Connection::readable()
{
    return _selection & SELECT_READ;
}

void
FromSniffers::Connection::socket_recv()
{
    assert(!_finished);

    // try to ensure at least 32K of recv space
    if (buffer_remaining(_inbuf) < 32*1024)
        buffer_compact(_inbuf);

    ssize_t len = recv(_fd, buffer_tail(_inbuf), buffer_remaining(_inbuf), 0);
    if (len == -1) {
        if (errno != EAGAIN) {
            _log->strerror("recv() on socket %d (%s)", _fd, _hostname.c_str());
            _finished = true;
            return;
        }
        // else, errno == EAGAIN which we just ignore
    } else if (len == 0) {  // EOF
        _log->info("EOF received from %s", _hostname.c_str());
        _finished = true;
    } else {
        // recv() succeeded
        assert(len > 0);

        _last_recv = Timestamp::now();
        _parent->_byte_count += len;
        _parent->_byte_rate.update(len);

        int rv = buffer_expand(_inbuf, len);
        assert(rv == 0);

        // if the connection has been marked invalid (for example, due to a
        // protocol error) then we just throw away everything we receive
        // subsequently; the only reason we don't terminate the connection right
        // off is that we want to let the client disconnect so we are basically
        // just waiting for an EOF
        if (_invalid) {
            buffer_empty(_inbuf);
            buffer_empty(_pktbuf);
        } else {
            int n_msgs, n_pcaps;
            process_buffer(_inbuf, &n_msgs, &n_pcaps);
            Timestamp end = Timestamp::now();
            _log->debug("processed %d messages (%d pcaps) from inbuf in %s sec",
                n_msgs, n_pcaps, (end-_last_recv).unparse().c_str());
        }
    }
}

void
FromSniffers::Connection::socket_send()
{
    assert(_outq.size() > 0);
    assert(!_finished);

    String cmd = _outq.front();
    assert(_sent < cmd.length());
    size_t to_send = cmd.length() - _sent;

    ssize_t len = send(_fd, cmd.data() + _sent, to_send, 0);
    if (len == -1) {
        if (errno != EAGAIN) {
            _log->strerror("send() on socket %d (%s)", _fd, _hostname.c_str());
            _finished = true;
            return;
        }
        // else, errno == EAGAIN which we just ignore
    }

    // else, send() succeeded
    assert(len > 0);

    _sent += len;
    if (_sent == cmd.length()) {
        // done sending this entire command
        _outq.pop_front();
        _sent = 0;
    }

    if (_outq.size() == 0) {
        _parent->remove_select(_fd, SELECT_WRITE);
        _selection &= (~SELECT_WRITE);
    }
}

int
FromSniffers::Connection::send_disconnect()
{
    size_t reqlen = sizeof(struct argos_net_closeconn_msg);
    struct argos_net_closeconn_msg *msg = (struct argos_net_closeconn_msg*)
        malloc(reqlen);
    if (msg == NULL) die("malloc failure");

    msg->msgtype = htons(ARGOS_NET_CLOSECONN_MSGTYPE);
    msg->msglen = htonl(reqlen);

    _log->debug("sending close-connection message to %s", _hostname.c_str());
    enqueue_cmd((u_char*)msg, reqlen);
    return 0;
}

inline bool
FromSniffers::Connection::writable()
{
    return _selection & SELECT_WRITE;
}


/*
 * Private Methods
 */

bool
FromSniffers::Connection::decompress_packets(uint8_t algorithm, const u_char *inptr,
    uint32_t inlen, u_char *outptr, uint32_t orig_len)
{
    String alg_name;
    uint32_t outlen = 0;
    Timestamp start = Timestamp::now();

    switch (algorithm) {
    case ARGOS_NET_COMPRESS_NONE:
        alg_name = "memcpy";
        memcpy(outptr, inptr, inlen);
        outlen = inlen;
        break;

    case ARGOS_NET_COMPRESS_LZO: {
        alg_name = "LZO";

        lzo_uint lzo_outlen = orig_len;  // initial value doesn't seem to matter
        int rv = lzo1x_decompress(inptr, inlen, outptr, &lzo_outlen, NULL);
        if (rv != LZO_E_OK) {
            // according to LZO documentation, this "should never happen"
            protocol_error(EIO, "lzo1x_decompress failed: %d", rv);
            return false;
        }
        outlen = lzo_outlen;
        break;
    }
    case ARGOS_NET_COMPRESS_QUICKLZ: {
        alg_name = "QuickLZ";
        outlen = qlz_decompress((const char*)inptr, outptr, qlz_scratch);
        break;
    }
    default:
        protocol_error(EINVAL, "unknown compression algorithm: %d", algorithm);
        _invalid = true;
        return false;
    }

    Timestamp elapsed = Timestamp::now() - start;

    if (outlen != orig_len) {
        // uh oh - this is bad
        protocol_error(EIO, "[%s] decompression returned %u bytes, expected %u",
            alg_name.c_str(), orig_len, outlen);
        return false;
    }

    float elapsed_msec = elapsed.usecval() / (float)1000;

    _log->debug("[%s] decompress %u bytes to %u in %.2f ms (%.2f MB/s)",
        alg_name.c_str(), inlen, outlen, elapsed_msec,
        ((orig_len/elapsed_msec)*1000)/(1024*1024));

    int rv = buffer_expand(_pktbuf, orig_len);
    assert(rv == 0);

    return true;
}

void
FromSniffers::Connection::process_buffer(struct buffer *b, int *msg_count,
    int *pcap_count)
{
    assert(!_invalid);

    if (msg_count != NULL) *msg_count = 0;
    if (pcap_count != NULL) *pcap_count = 0;

    // repeatedly parse messages out of the buffer until its empty or a partial
    // message is encountered
    while (buffer_len(b) >= sizeof(struct argos_net_minimal_msg)) {
        struct argos_net_minimal_msg *header =
            (struct argos_net_minimal_msg *)buffer_head(b);

        uint16_t msgtype = ntohs(header->msgtype);
        uint32_t msglen = ntohl(header->msglen);

        // check that message type and length are valid
        if (ARGOS_NET_VALIDATE_MSGTYPE(msgtype) == 0) {
            protocol_error(EBADMSG, "invalid message type received; type=%hu, len=%u",
                msgtype, msglen);
            _invalid = true;
            return;
        }

        if (ARGOS_NET_VALIDATE_MSGLEN(msgtype, msglen) == 0) {
            protocol_error(EBADMSG, "invalid message len received; type=%hu, len=%u",
                msgtype, msglen);
            _invalid = true;
            return;
        }

        if (msglen > buffer_len(b)) {
            // entire message not yet received
            if (msglen > buffer_size(b)) {
                // error - message is bigger than the entire inbuf
                protocol_error(ENOBUFS, "inbuf too small for msgtype %hu (len=%u)",
                    msgtype, msglen);
                _invalid = true;
                return;
            }

            // wait for more bytes to arrive on socket
            break;
        }

        // sanity check: if we are processing the packet buffer, we should only
        // receive PCAP messages
        if (b == _pktbuf) {
            if (msgtype != ARGOS_NET_PCAP_MSGTYPE) {
                protocol_error(EPROTO, "msgtype x%02x received in packet buffer");
                _invalid = true;
                return;
            }
        }

        // full message received - for some messages, create a click packet
        WritablePacket *p = NULL;
        struct argos_sniff *sniff = NULL;

        if ((msgtype == ARGOS_NET_HANDSHAKE_MSGTYPE) ||
            (msgtype == ARGOS_NET_PCAP_MSGTYPE) ||
            (msgtype == ARGOS_NET_STATS_MSGTYPE)) {

            // special case: for pcap messages, skip the Argos header
            int skiplen = (msgtype == ARGOS_NET_PCAP_MSGTYPE) ?
                sizeof(struct argos_net_pcap_msg) : 0;

            p = Packet::make(_parent->_headroom, buffer_head(b) + skiplen,
                msglen - skiplen, 0);

            if (p == NULL) {
                _log->error("Packet::make() failed (size=%d)",
                    _parent->_headroom + msglen - skiplen);
                return;
            }

            // create an Argos annotation area (not all fields in the annotation
            // area apply to all message types)
            sniff = ARGOS_SNIFF_ANNO(p);
            sniff->magic = ARGOS_SNIFF_MAGIC;
            struct in_addr ia = _address.in_addr();
            memcpy(&sniff->sniffer, &ia, sizeof(struct in_addr));
        }

        // update stats maintained by parent
        _parent->_count++;
        _parent->_rate.update(1);

        // now to type-specific processing
        switch (msgtype) {
        case ARGOS_NET_HANDSHAKE_MSGTYPE: {
            // sanity check: did we already receive a handshake from this
            // sniffer node?
            if (_handshook) {
                _parent->checked_output_push(FROMSNIFFERS_PORT_BADMSG, p);
                protocol_error(EPROTO, "multiple handshake messages received");
                _invalid = true;
                p->kill();
                return;
            }

            // verify magic number and remote sniffer's current version
            struct argos_net_handshake_msg *msg =
                (struct argos_net_handshake_msg*)header;

            if (ntohl(msg->magicnum) != ARGOS_NET_MAGICNUM) {
                _parent->checked_output_push(FROMSNIFFERS_PORT_BADMSG, p);
                protocol_error(EINVAL, "invalid magic number (%X)", ntohl(msg->magicnum));
                _invalid = true;
                p->kill();
                return;
            }

            if ((ntohs(msg->major_version) != ARGOS_MAJOR_VERSION) ||
                ntohs(msg->minor_version) != ARGOS_MINOR_VERSION) {
                protocol_error(EACCES, "invalid version (%d.%d), expected %d.%d",
                    ntohs(msg->major_version), ntohs(msg->minor_version),
                    ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION);
                _invalid = true;
                p->kill();
                return;
            }

            _handshook = true;
            int dlt = ntohl(msg->dlt);

            if (dlt != _parent->dlt()) {
                protocol_error(EINVAL, "invalid dlt (%d), expected %d", dlt,
                    _parent->dlt());
                _invalid = true;
                p->kill();
                return;
            }

            _log->info("valid handshake received from %s", _hostname.c_str());

            // is this the first time this client is connecting?  if so, send a
            // close-connection message to force the client to force network
            // buffers (see comments for _client_history)
            if (_parent->_client_history.findp(_address) == NULL) {
                _log->info("first connection from %s -- closing connection to"
                    " flush buffers", _hostname.c_str());

                send_bpf_filter(true);  // close bpf filter
                send_disconnect();
                _parent->_client_history.insert(_address, 1);
                _invalid = true;
                p->kill();
                return;
            } else {
                _log->debug("not first connection from %s -- accepting normally");
            }

            // now that this sniffer is validated, send the current BPF filters
            send_bpf_filter();

            // forward handshake in case anyone else wants to look at it
            _parent->checked_output_push(FROMSNIFFERS_PORT_HANDSHAKE, p);
            break;
        }

        case ARGOS_NET_PCAP_MSGTYPE: {
            if (!_handshook) {
                _parent->checked_output_push(FROMSNIFFERS_PORT_BADMSG, p);
                protocol_error(EPROTO, "pcap message received before handshake");
                _invalid = true;
                p->kill();
                return;
            }

            struct argos_net_pcap_msg *msg =
                (struct argos_net_pcap_msg*)header;

            sniff->channel = msg->channel;

            SET_EXTRA_LENGTH_ANNO(p, ntohl(msg->msglen) - ntohl(msg->caplen));

            if (ntohl(msg->caplen) != (msglen - sizeof(struct argos_net_pcap_msg))) {
                _log->error("msg->caplen (%u) != msglen (%u) - struct size (%u)",
                    ntohl(msg->caplen), msglen, sizeof(struct argos_net_pcap_msg));
                abort();
            }

            struct timeval tv;
            tv.tv_sec = ntohl(msg->ts_sec);
            tv.tv_usec = ntohl(msg->ts_usec);
            p->set_timestamp_anno(Timestamp(tv));
            _parent->checked_output_push(FROMSNIFFERS_PORT_PCAP, p);

            if (pcap_count != NULL) (*pcap_count)++;
            break;
        }

        case ARGOS_NET_STATS_MSGTYPE: {
            if (!_handshook) {
                _parent->checked_output_push(FROMSNIFFERS_PORT_BADMSG, p);
                protocol_error(EPROTO, "stats message received before handshake");
                _invalid = true;
                p->kill();
                return;
            }

            struct argos_net_stats_msg *msg =
                (struct argos_net_stats_msg*)header;

            struct timeval tv;
            tv.tv_sec = ntohl(msg->ts_sec);
            tv.tv_usec = ntohl(msg->ts_usec);
            p->set_timestamp_anno(Timestamp(tv));
            _parent->checked_output_push(FROMSNIFFERS_PORT_STATS, p);
            break;
        }

        case ARGOS_NET_ERROR_MSGTYPE: {
            struct argos_net_error_msg *msg =
                (struct argos_net_error_msg*)header;

            uint8_t errnum = msg->errnum;
            size_t hdrlen = sizeof(struct argos_net_error_msg);
            uint16_t slen = ntohl(msg->msglen) - hdrlen;
            String errmsg = String((char*)(buffer_head(b) + hdrlen), slen);
            _log->warning("sniffer error %d (%s): %s", errnum, _address.s().c_str(), errmsg.c_str());
            break;
        }

        case ARGOS_NET_COMPRESS_MSGTYPE: {
            struct argos_net_compress_msg *msg =
                (struct argos_net_compress_msg*)header;

            uint32_t origlen = ntohl(msg->orig_len);

            buffer_compact(_pktbuf);
            if (buffer_remaining(_pktbuf) < origlen) {
                protocol_error(ENOBUFS, "pktbuf too small for current contents"
                    " (%d) plus next compression block (%u)", buffer_len(_pktbuf),
                    origlen);
                _invalid = true;
                return;
            }

            size_t hdrlen = sizeof(struct argos_net_compress_msg);
            size_t blocklen = msglen - hdrlen;

            bool ok = decompress_packets(msg->algorithm, buffer_head(b) + hdrlen,
                blocklen, buffer_tail(_pktbuf), origlen);

            if (ok) {
                // now that we have concatenated some more uncompressed packet
                // data into _pktbuf, process it to try and consume some pcap
                // messages
                process_buffer(_pktbuf, msg_count, pcap_count);
                if (_invalid) return;  // packet buffer might fail too
            } else {
                // decompression failed
                _invalid = true;
                return;
            }
            break;
        }

        default:
            protocol_error(EBADMSG, "unsupported message type (%hu)", msgtype);
            _invalid = true;
            return;
        }

        int rv = buffer_discard(b, msglen);
        assert(rv == 0);
        if (msg_count != NULL) (*msg_count)++;
    }
}

void
FromSniffers::Connection::protocol_error(uint8_t errnum, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *str;
    if (vasprintf(&str, fmt, ap) == -1) {
        _log->strerror("snprintf");
        return;
    }
    va_end(ap);

    _log->error("%s -> %s", _hostname.c_str(), str);

    size_t bodylen = strlen(str);
    if (bodylen > ARGOS_NET_MAX_ERR_LEN) {
        _log->error("error message length (%d) exceeds protocol maximum",
            bodylen, ARGOS_NET_MAX_ERR_LEN);
        free(str);
        return;
    }

    size_t hdrlen = sizeof(struct argos_net_error_msg);
    size_t reqlen = hdrlen + bodylen;
    struct argos_net_error_msg *msg = (struct argos_net_error_msg*)
        malloc(reqlen);
    if (msg == NULL) die("malloc failure");

    msg->msgtype = htons(ARGOS_NET_ERROR_MSGTYPE);
    msg->msglen = htonl(reqlen);
    msg->errnum = errnum;

    memcpy((u_char*)msg + hdrlen, str, bodylen);
    free(str);

    enqueue_cmd((u_char*)msg, reqlen);
}

void
FromSniffers::Connection::send_bpf_filter(bool close)
{
    String closed_bpf_expr = ARGOS_NET_CLOSEFD_BPF;

    String *bpf;
    if ((_parent->_agg_bpf_count == 0) || close) {
        bpf = &closed_bpf_expr;
        _log->debug("closing BPF on %s", _hostname.c_str());
    } else {
        bpf = &(_parent->_agg_bpf_filter);
        _log->debug("setting BPF on %s", _hostname.c_str());
    }

    assert(bpf != NULL);
    size_t bodylen = bpf->length();
    if (bodylen > ARGOS_NET_MAX_BPF_LEN) {
        _log->error("bpf expression length (%d) exceeds protocol maximum",
            bodylen, ARGOS_NET_MAX_BPF_LEN);
        return;
    }

    size_t hdrlen = sizeof(struct argos_net_setbpf_msg);
    size_t reqlen = hdrlen + bodylen;
    struct argos_net_setbpf_msg *msg = (struct argos_net_setbpf_msg*)
        malloc(reqlen);
    if (msg == NULL) die("malloc failure");

    msg->msgtype = htons(ARGOS_NET_SETBPF_MSGTYPE);
    msg->msglen = htonl(reqlen);
    memcpy(((u_char*)msg) + hdrlen, bpf->c_str(), bodylen);

    enqueue_cmd((u_char*)msg, reqlen);
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
ELEMENT_REQUIRES(buffer)
ELEMENT_REQUIRES(quicklz)
EXPORT_ELEMENT(FromSniffers)
ELEMENT_LIBS(-L../build/lib -llzo2)
