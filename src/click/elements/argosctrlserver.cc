/*
 * argosctrlserver.{cc,hh} -- accepts connections from argos sniffers and
 *                            responds with 'start-click' commands
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "argosctrlserver.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pcap.h>
#include "iputil.hh"
#include "argos/common.h"
#include "argos/net_proto.h"
#include "argos/version.h"
CLICK_DECLS


// *************************************
// ArgosCtrlServer class methods
// *************************************

ArgosCtrlServer::ArgosCtrlServer()
    : _portno(ARGOS_NET_DEF_SERVER_PORT), _svrsock(-1), _task(this), _log(NULL)
{
}

ArgosCtrlServer::~ArgosCtrlServer()
{
    if (_log != NULL) delete _log;
}

enum { H_CLIENTS, H_DISCONNECT_ALL };

void
ArgosCtrlServer::add_handlers()
{
    add_read_handler("clients", read_handler, (void*)H_CLIENTS);
    add_write_handler("disconnect_all", write_handler, (void*)H_DISCONNECT_ALL);
}

void
ArgosCtrlServer::cleanup(CleanupStage)
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
        HashMap<int, ArgosConnection*>::iterator iter = _fd_hash.begin();
        if (!iter.live()) break;
        ArgosConnection *conn = iter.value();
        int fd = iter.pair()->key;
        _fd_hash.erase(fd);
        
        delete conn;
        close_fd(fd);
    }
}

int
ArgosCtrlServer::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String filename, ipliststr, loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "NODE_FILE", cpkM, cpString, &filename,
            "PORT", 0, cpTCPPort, &_portno,
            "ALLOW", 0, cpString, &ipliststr,
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

    FILE *fi = fopen(filename.c_str(), "r");
    if (fi == NULL)
        return errh->error("failed to open %s: %s", filename.c_str(),
            strerror(errno));

    char cbuf[10485760];  // 10 MB
    size_t len = fread(cbuf, 1, sizeof(cbuf), fi);
    if (len >= sizeof(cbuf))
        return errh->error("node router too big (exceeds read buffer size)");

    if (ferror(fi))
        return errh->error("fread failed: %s", strerror(errno));

    assert(strlen(cbuf) == len);
    assert(feof(fi));

    if (fclose(fi) != 0)
        return errh->error("failed to close %s: %s", filename.c_str(),
            strerror(errno));

    _start_click_msg_len = sizeof(struct argos_net_startclick_msg) + len;

    char *ptr = (char*)malloc(_start_click_msg_len);
    if (ptr == NULL)
        return errh->error("malloc(%d) failed", _start_click_msg_len);

    Vector<String> ips;
    cp_spacevec(ipliststr, ips);

    for (int i=0; i < ips.size(); i++) {
        IPAddress ip;
        if (cp_ip_address(ips[i], &ip, this))
            _allowed_ips.push_back(ip);
        else
            return errh->error("failed to parse %s as IP address",
                ips[i].c_str());
    }

    // we use the current time as the click-config key since this will
    // (generally) be different for each invocation
    _start_click_msg = (struct argos_net_startclick_msg*)ptr;
    _start_click_msg->msgtype = htons(ARGOS_NET_STARTCLICK_MSGTYPE);
    _start_click_msg->msglen = htonl(_start_click_msg_len);
    _start_click_msg->key = htonl(time(NULL));
    memcpy(ptr + sizeof(struct argos_net_startclick_msg), cbuf, len);

    _log->debug("read %d bytes from node file %s", len, filename.c_str());

    return 0;
}

int
ArgosCtrlServer::initialize(ErrorHandler *errh)
{
    _log->info("Initializing.  Argos version %d.%02d  (built %s %s)",
        ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION, __DATE__, __TIME__);

    // open socket, set options
    _svrsock = socket(AF_INET, SOCK_STREAM, 0);
    if (_svrsock < 0)
        return initialize_socket_error(errh, "socket");

    int on = 1;
    if (setsockopt(_svrsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
        return initialize_socket_error(errh, "setsockopt(SO_REUSEADDR)");

    // disable Nagle algorithm
    int nodelay = 1;
    if (setsockopt(_svrsock, IP_PROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
        return initialize_socket_error(errh, "setsockopt(TCP_NODELAY)");

    struct addrinfo hints, *servinfo;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char portstr[32];
    snprintf(portstr, sizeof(portstr), "%d", _portno);

    int rv = getaddrinfo(NULL, portstr, &hints, &servinfo);
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
ArgosCtrlServer::run_task(Task *)
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
ArgosCtrlServer::selected(int fd)
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

        ArgosConnection *conn = new ArgosConnection(sock, &addr, this);

        // ensure that ArgosConnection creation was successful
        if (conn->finished()) {
            // something failed in ArgosConnection ctor
            delete conn;
            return;
        }

        // shouldn't be needed since we only call recv() and send() when the fd
        // has been selected, but set it to be defensive in case click screws up
        if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
            _log->strerror("fnctl(O_NONBLOCK)");
            close_fd(sock);
            return;
        }

        // prevent socket from throwing SIGPIPE signals
        int on = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&on,
                sizeof(on)) < 0) {
            _log->strerror("setsockopt(SO_NOSIGPIPE)");
            close_fd(sock);
            return;
        }

        _log->info("accepted connection from %s (%s) on fd %d",
            conn->name().c_str(), conn->address().unparse().c_str(), sock);

        assert(_fd_hash.find(sock) == NULL);
        _fd_hash.insert(sock, conn);
    } else {  // fd != _svrsock
        ArgosConnection *conn = _fd_hash.find(fd);
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

/*
 * Protected Methods
 */

int
ArgosCtrlServer::disconnect_all_handler(const String &, ErrorHandler *)
{
    _log->info("write-handler request to disconnect all clients");

    // stop accepting new connections
    remove_select(_svrsock, SELECT_READ);

    HashMap<int, ArgosConnection*>::iterator iter = _fd_hash.begin();
    for (; iter != _fd_hash.end(); iter++) {
        ArgosConnection *conn = iter.value();
        (void) conn->send_disconnect();
    }

    return 0;
}

String
ArgosCtrlServer::read_handler(Element *e, void *thunk)
{
    const ArgosCtrlServer *elt = static_cast<ArgosCtrlServer *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_CLIENTS: {
        StringAccum sa;
        HashMap<int, ArgosConnection*>::const_iterator iter = elt->_fd_hash.begin();
        for (; iter != elt->_fd_hash.end(); iter++) {
            sa << iter.value()->address().unparse() << " ("
               << iter.value()->name() << ") since "
               << iter.value()->connect_time().unparse() << "\n";
        }
        
        return sa.take_string();
    }
    default:
        return "internal error (bad thunk value)";
    }
}

int
ArgosCtrlServer::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    ArgosCtrlServer *elt = static_cast<ArgosCtrlServer*>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_DISCONNECT_ALL:
        return elt->disconnect_all_handler(s_in, errh);
    default:
        return errh->error("internal error (bad thunk value)");
    }
}


/*
 * Private Methods
 */

void
ArgosCtrlServer::close_fd(int fd)
{
    do {
        if (close(fd) == -1) {
            if (errno == EINTR)
                continue;
            else
                _log->strerror("close() on socket %d", fd);
        }
    } while (0);
}

void
ArgosCtrlServer::delete_connection(ArgosConnection *conn)
{
    remove_select(conn->fd(), SELECT_READ | SELECT_WRITE);

    bool removed = _fd_hash.erase(conn->fd());
    assert(removed);

    _log->info("connection closed to %s (%s) on fd %d", conn->name().c_str(),
        conn->address().unparse().c_str(), conn->fd());

    close_fd(conn->fd());
    delete conn;
}

int
ArgosCtrlServer::initialize_socket_error(ErrorHandler *errh, const char *syscall)
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


// *************************************
// ArgosConnection class methods
// *************************************

ArgosConnection::ArgosConnection(int fd, const struct sockaddr_in *addr,
    ArgosCtrlServer *parent, uint32_t inbuflen, uint32_t outbuflen)
{
    _parent = parent;
    _addr = IPAddress(addr->sin_addr);
    _sock_addr = _addr;
    _connect_time = Timestamp::now();
    _fd = fd;
    _finished = false;
    _handshook = false;
    _invalid = false;
    _log = _parent->_log;

    _inbuf = buffer_create(inbuflen);
    if (_inbuf == NULL) {
        // malloc failed - terminate right away
        _log->debug("buffer_create(%d) failed in ArgosConnection ctor", inbuflen);
        _finished = true;
        return;
    }

    _outbuf = buffer_create(outbuflen);
    if (_outbuf == NULL) {
        // malloc failed - terminate right away
        _log->debug("buffer_create(%d) failed in ArgosConnection ctor", outbuflen);
        _finished = true;
        return;
    }

    StoredErrorHandler errh = StoredErrorHandler();
    if (ip_lookup_hostname(_sock_addr, 0, &_name, &errh) == 0) {
        // keep only the first label of the hostname
        int colon = _name.find_left('.');
        if (colon > 0)
            _name = _name.substring(0, colon);
        else if (_name.length() == 0)
            _name = "?";
    } else {
        if (errh.has_error())
            _log->error("%s", errh.get_last_error().c_str());
        _name = _addr.unparse();
    }

    // only select for readability right now (since there is no data to send)
    _parent->add_select(fd, Element::SELECT_READ);
    _selection = Element::SELECT_READ;
}

ArgosConnection::~ArgosConnection()
{
    if (_inbuf != NULL) buffer_destroy(_inbuf);
    if (_outbuf != NULL) buffer_destroy(_outbuf);
}

inline int
ArgosConnection::enqueue_cmd(const u_char *data, size_t len)
{
    if (buffer_write(_outbuf, data, len) == -1)
        return -1;

    if ((_selection & Element::SELECT_WRITE) == 0) {
        _selection |= Element::SELECT_WRITE;
        _parent->add_select(_fd, Element::SELECT_WRITE);
    }

    return 0;
}

void
ArgosConnection::socket_recv()
{
    assert(!_finished);

    // try to ensure at least 32K of recv space
    if (buffer_remaining(_inbuf) < 32*1024)
        buffer_compact(_inbuf);

    ssize_t len = recv(_fd, buffer_tail(_inbuf), buffer_remaining(_inbuf), 0);
    if (len == -1) {
        switch (errno) {
        case EAGAIN:
            // just ignore it
            break;

        case ECONNRESET:
        case ETIMEDOUT:
            // these errors can happen as a normal consequence of network links
            // going up and down; we issue a warning instead of an error, but we
            // still need to shut down the connection because its dead now
            // (ETIMEDOUT is documented in the socket(2) man page, not recv(2))
            _log->info("recv() on socket %d (%s): %s", _fd, _name.c_str(),
                strerror(errno));
            _finished = true;
            break;

        default:
            // all other errors are unexpected; they probably indicate a
            // programming error so we issue critical-level errors
            _log->critical("recv() on socket %d (%s): %s", _fd, _name.c_str(),
                strerror(errno));
            _finished = true;
            break;
        }
    } else if (len == 0) {  // EOF
        _log->info("EOF received from %s", _name.c_str());
        _finished = true;
    } else {
        // recv() succeeded
        assert(len > 0);

        int rv = buffer_expand(_inbuf, len);
        assert(rv == len);

        // if the connection has been marked invalid (for example, due to a
        // protocol error) then we just throw away everything we receive
        // subsequently; the only reason we don't terminate the connection right
        // off is that we want to let the client disconnect so we are basically
        // just waiting for an EOF
        if (_invalid) {
            buffer_empty(_inbuf);
        } else {
            process_inbuf();
            if (buffer_len(_inbuf) == 0)
                buffer_compact(_inbuf);
        }
    }
}

void
ArgosConnection::socket_send()
{
    size_t to_send = buffer_len(_outbuf);
    assert(to_send > 0);
    assert(!_finished);
    ssize_t len = send(_fd, buffer_head(_outbuf), to_send, 0);
    if (len == -1) {
        switch (errno) {
        case EAGAIN:
            // just ignore it
            break;

        case ENOBUFS:
        case EPIPE:
            // these errors can occur "normally" due to typical, transient
            // errors (such as nodes being temporarily offline)
            _log->info("send() on socket %d (%s): %s", _fd, _name.c_str(),
                strerror(errno));
            _finished = true;
            break;

        case ECONNREFUSED:
        case EHOSTUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
            // these errors are possible, but are rare and may indicate a more
            // serious problem
            _log->strerror("send() on socket %d (%s)", _fd, _name.c_str());
            _finished = true;
            break;

        default:
            // anything else is unexpected and may indicate a programming error
            _log->critical("send() on socket %d (%s): %s", _fd, _name.c_str(),
                strerror(errno));
            _finished = true;
        }
    } else {
        // send() succeeded
        assert(len > 0);

        buffer_discard(_outbuf, len);
        buffer_compact(_outbuf);

        if (buffer_len(_outbuf) == 0) {
            _parent->remove_select(_fd, Element::SELECT_WRITE);
            _selection &= (~Element::SELECT_WRITE);
        }
    }
}

int
ArgosConnection::send_disconnect()
{
    size_t reqlen = sizeof(struct argos_net_closeconn_msg);
    struct argos_net_closeconn_msg *msg = (struct argos_net_closeconn_msg*)
        malloc(reqlen);
    if (msg == NULL) {
        _log->error("malloc(%u): %s", reqlen, strerror(errno));
        return -1;
    }

    msg->msgtype = htons(ARGOS_NET_CLOSECONN_MSGTYPE);
    msg->msglen = htonl(reqlen);

    _log->debug("sending close-connection message to %s", _name.c_str());
    enqueue_cmd((u_char*)msg, reqlen);
    free(msg);
    return 0;
}


/*
 * Private Methods
 */

void
ArgosConnection::process_inbuf(void)
{
    assert(!_invalid);

    // repeatedly parse messages out of the buffer until its empty or a partial
    // message is encountered
    while (buffer_len(_inbuf) >= sizeof(struct argos_net_minimal_msg)) {
        struct argos_net_minimal_msg *header =
            (struct argos_net_minimal_msg *)buffer_head(_inbuf);

        uint16_t msgtype = ntohs(header->msgtype);
        uint32_t msglen = ntohl(header->msglen);

        // check that message type and length are valid
        if (ARGOS_NET_VALIDATE_MSGTYPE(msgtype) == 0) {
            protocol_error(EBADMSG, "invalid message type received; type=%hu, len=%u",
                msgtype, msglen);
            (void) send_disconnect();
            _invalid = true;
            return;
        }

        if (ARGOS_NET_VALIDATE_MSGLEN(msgtype, msglen) == 0) {
            protocol_error(EBADMSG, "invalid message len received; type=%hu, len=%u",
                msgtype, msglen);
            (void) send_disconnect();
            _invalid = true;
            return;
        }

        if (msglen > buffer_len(_inbuf)) {
            // complete message not yet received
            if (msglen > buffer_size(_inbuf)) {
                // error - message is bigger than the entire inbuf
                protocol_error(ENOBUFS, "inbuf too small for msgtype %hu (len=%u)",
                    msgtype, msglen);
                (void) send_disconnect();
                _invalid = true;
                return;
            }

            // wait for more bytes to arrive on socket
            break;
        }

        // full message received - now to type-specific processing
        switch (msgtype) {
        case ARGOS_NET_HANDSHAKE_MSGTYPE: {
            // sanity check: did we already receive a handshake from this node?
            if (_handshook) {
                protocol_error(EPROTO, "multiple handshakes messages received");
                (void) send_disconnect();
                _invalid = true;
                return;
            }

            // verify magic number and remote node's current version
            struct argos_net_handshake_msg *msg =
                (struct argos_net_handshake_msg*)header;

            if (ntohl(msg->magicnum) != ARGOS_NET_MAGICNUM) {
                protocol_error(EINVAL, "invalid magic number (0x%08X)", ntohl(msg->magicnum));
                (void) send_disconnect();
                _invalid = true;
                return;
            }

            if ((ntohs(msg->major_version) != ARGOS_MAJOR_VERSION) ||
                ntohs(msg->minor_version) != ARGOS_MINOR_VERSION) {
                protocol_error(EACCES, "invalid version (%d.%02d), expected %d.%02d",
                    ntohs(msg->major_version), ntohs(msg->minor_version),
                    ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION);
                (void) send_disconnect();
                _invalid = true;
                return;
            }

            _handshook = true;
            _addr = IPAddress(msg->ip);
            // note: dlt is ignored, unlike in the FromSniffer element

            StoredErrorHandler errh = StoredErrorHandler();
            if (ip_lookup_hostname(_addr, 0, &_name, &errh) == 0) {
                // keep only the first label of the hostname
                int colon = _name.find_left('.');
                if (colon > 0)
                    _name = _name.substring(0, colon);
                else if (_name.length() == 0)
                    _name = "?";
            } else {
                if (errh.has_error())
                    _log->error("%s", errh.get_last_error().c_str());
                _name = _addr.unparse();
            }

            for (int i=0; i < _parent->_denied_ips.size(); i++) {
                if (_parent->_denied_ips[i] == _addr) {
                    // see comments below for handling denied IP addresses
                    _log->info("valid handshake received from %s (%s in DENY list)"
                        " -- refusing node router", _name.c_str(),
                        _addr.unparse().c_str());
                    // send errnum=0 so that the argosniffer won't quit on us
                    (void) send_error(0, "IP in DENY list");
                    break;
                }
            }

            if (_parent->_allowed_ips.size() > 0) {
                bool found = false;
                for (int i=0; i < _parent->_allowed_ips.size(); i++) {
                    if (_parent->_allowed_ips[i] == _addr) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    // when we receive a connection from a node not in the ALLOW
                    // list, we don't simpy disconnect right away as that would
                    // probably just lead to the client reconnecting over and
                    // over - instead, we "lead him along" by leaving the
                    // connection open but refusing to send him the click
                    // configuration which effectively makes him dormant
                    _log->info("valid handshake received from %s (%s not in ALLOW list)"
                        " -- refusing node router", _name.c_str(),
                        _addr.unparse().c_str());
                    // send errnum=0 so that the argosniffer won't quit on us
                    (void) send_error(0, "IP not in ALLOW list");
                    break;
                }
            }

            if (_addr != _sock_addr)
                _log->info("client %s (%s) is connected via %s", _name.c_str(),
                    _addr.unparse().c_str(), _sock_addr.unparse().c_str());
            
            _log->info("valid handshake received from %s -- sending node router (%d bytes)",
                _name.c_str(), _parent->_start_click_msg_len);

            if (enqueue_cmd((u_char*)_parent->_start_click_msg, _parent->_start_click_msg_len) != 0)
                _log->error("failed to enqueue node router message (%d bytes)",
                    _parent->_start_click_msg_len);
            break;
        }

        case ARGOS_NET_ERROR_MSGTYPE: {
            struct argos_net_error_msg *msg =
                (struct argos_net_error_msg*)header;

            uint8_t errnum = ntohs(msg->errnum);
            size_t hdrlen = sizeof(struct argos_net_error_msg);
            uint16_t slen = ntohl(msg->msglen) - hdrlen;
            String errmsg = String((char*)(buffer_head(_inbuf) + hdrlen), slen);
            _log->error("sniffer error %d (%s): %s", errnum, _name.c_str(), errmsg.c_str());
            break;
        }

        default:
            _log->warning("received unexpected msgtype %d from %s", msgtype,
                _name.c_str());
            (void) send_disconnect();
            _invalid = true;
            return;
        }

        int rv = buffer_discard(_inbuf, msglen);
        assert(rv == (int)msglen);
    }
}

void
ArgosConnection::protocol_error(uint8_t errnum, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *str;
    if (vasprintf(&str, fmt, ap) == -1) {
        _log->strerror("vasprintf");
        return;
    }
    va_end(ap);

    _log->error("%s -> %s", _name.c_str(), str);

    (void) send_error(errnum, "%s", str);
    free(str);
}

int
ArgosConnection::send_error(uint8_t errnum, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *str;
    if (vasprintf(&str, fmt, ap) == -1) {
        _log->strerror("vasprintf");
        return -1;
    }
    va_end(ap);

    size_t bodylen = strlen(str);
    if (bodylen > ARGOS_NET_MAX_ERR_LEN) {
        _log->error("error message length (%d) exceeds protocol maximum",
            bodylen, ARGOS_NET_MAX_ERR_LEN);
        free(str);
        return -1;
    }

    size_t hdrlen = sizeof(struct argos_net_error_msg);
    size_t reqlen = hdrlen + bodylen;
    struct argos_net_error_msg *msg = (struct argos_net_error_msg*)
        malloc(reqlen);
    if (msg == NULL) {
        _log->error("malloc(%u): %s", reqlen, strerror(errno));
        return -1;
    }

    msg->msgtype = htons(ARGOS_NET_ERROR_MSGTYPE);
    msg->msglen = htonl(reqlen);
    msg->errnum = htons(errnum);

    memcpy((u_char*)msg + hdrlen, str, bodylen);
    free(str);

    enqueue_cmd((u_char*)msg, reqlen);
    return 0;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(buffer userlevel)
EXPORT_ELEMENT(ArgosCtrlServer)
