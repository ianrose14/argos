/*
 * proxyserver.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "proxyserver.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
CLICK_DECLS

ProxyServer::ProxyServer(Element *elt)
    : _elt(elt), _log(NULL), _sock(-1), _inbufsz(256*1024),
      _headroom(0)
{
    _trace_cpu = false;
    _start_cpu_time = Timestamp(0);
    _total_cpu_time = Timestamp(0);
    _child_cpu_time = Timestamp(0);
}

ProxyServer::~ProxyServer()
{
    close();
    if (_log != NULL) delete _log;
}

void
ProxyServer::close()
{
    HashMap<int, ProxyReceiver*>::iterator iter = _fd_hash.begin();
    for (; iter != _fd_hash.end(); iter++) {
        ProxyReceiver *receiver = iter.value();
        // ProxyReceiver::close() should call our handle_close method, which is
        // where we do the actual deletion of the receiver object
        receiver->close();
    }

    close_socket(_sock);
    _sock = -1;
}

ProxyReceiver *
ProxyServer::create_proxy_receiver(int fd, const struct sockaddr_in *addr,
    size_t bufsize)
{
    // default implementation:
    ProxyReceiver *receiver = new ProxyReceiver(fd, addr, bufsize, this);
    receiver->set_headroom(_headroom);
    receiver->set_logger(_log);
    return receiver;
}

void
ProxyServer::get_connections(Vector<ProxyReceiver*> *vec) const
{
    HashMap<int, ProxyReceiver*>::const_iterator iter = _fd_hash.begin();
    for (; iter != _fd_hash.end(); iter++) {
        vec->push_back(iter.value());
    }
}

bool
ProxyServer::handle_accept(int fd, const struct sockaddr_in *)
{
    // default implementation:
    _elt->add_select(fd, Element::SELECT_READ);
    return true;
}

void
ProxyServer::handle_close(int fd)
{
    ProxyReceiver *receiver = _fd_hash.find(fd);
    if (receiver == NULL) {
        _log->error("in ProxyServer::handle_close, fd (%d) not found in _fd_hash", fd);
        return;
    }

    bool found = _fd_hash.erase(fd);
    assert(found);

    _elt->remove_select(fd, Element::SELECT_READ);
    delete receiver;
}

// if, during this method, control is passed to any other elements (e.g. a
// packet is pushed), the total cpu time consumed during loss of control should
// be added to ext_cpu (if its not NULL)
void
ProxyServer::handle_packet(Packet *p, const struct sockaddr_in *)
{
    // default implementation:

    Timestamp start;
    struct timespec tspec;
    if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
        start = Timestamp(tspec);
    } else {
        ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
            strerror(errno));
    }

    _elt->checked_output_push(0, p);

    if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
        Timestamp elapsed = Timestamp(tspec) - start;
        assert(elapsed >= 0);
        _child_cpu_time += elapsed;
    } else {
        ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
            strerror(errno));
    }
}

int
ProxyServer::listen(const struct sockaddr_in *addr)
{
    _addr = *addr;
    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0) {
        _log->strerror("socket");
        return -1;
    }

    int on = 1;
    if (setsockopt(_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        _log->strerror("setsockopt(SO_REUSEADDR)");
        return -1;
    }

    if (bind(_sock, (struct sockaddr*)&_addr, sizeof(_addr)) < 0) {
        _log->strerror("bind(%s:%d)", inet_ntoa(_addr.sin_addr), ntohs(_addr.sin_port));
        return -1;
    }

    // try to listen
    if (::listen(_sock, 5) < 0) {
        _log->strerror("listen");
        return -1;
    }

    // shouldn't be needed since we only call accept() when the fd has been
    // selected, but set it to be defensive in case click screws up
    if (fcntl(_sock, F_SETFL, O_NONBLOCK) == -1) {
        _log->warning("fcntl(O_NONBLOCK): %s", strerror(errno));
        // not treated as a fatal error
    }

    _log->info("listening for connections on %s:%d",
        inet_ntoa(_addr.sin_addr), ntohs(_addr.sin_port));

    _elt->add_select(_sock, Element::SELECT_READ);  // select for accept()

    // we use this method as the time when CPU timing should start, although
    // conceivably this may not always be the case (probably close though)
    _start_cpu_time = Timestamp::now();

    return 0;
}

bool
ProxyServer::selected(int fd)
{
    Timestamp start;
    struct timespec tspec;
    if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
        start = Timestamp(tspec);
    } else {
        ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
            strerror(errno));
    }

    // to ease the writing of CPU profiling code (avoiding multiple exit
    // points), the real work of this method is moved to handle_selected()
    bool rv = handle_selected(fd);

    if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
        Timestamp elapsed = Timestamp(tspec) - start;
        assert(elapsed >= 0);
        _total_cpu_time += elapsed;
    } else {
        ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
            strerror(errno));
    }

    return rv;
}

void
ProxyServer::stop_listening()
{
    // people often call stop_listening() in destructors, which might be called
    // before _log has been assigned to an object (if they are called due to an
    // early abort, such as due to a configuration error)
    if (_log != NULL)
        _log->info("stop_listening() called");
    _elt->remove_select(_sock, Element::SELECT_READ);
}

/*
 * Private Methods
 */
bool
ProxyServer::handle_selected(int fd)
{
    if (fd == _sock) {
        struct sockaddr client_addr;
        socklen_t client_addrlen = sizeof(client_addr);
        int client_fd = accept(_sock, &client_addr, &client_addrlen);
        if (client_fd == -1) {
            // note: EAGAIN and "real" socket errors happen to be handled
            // identically
            // TODO: eventually we might want to treat ECONNABORTED as a warning
            // instead of an error
            _log->strerror("accept");
            return true;
        }

        struct sockaddr_in *sin = (struct sockaddr_in*)&client_addr;

        _log->info("accepted connection from %s:%d on fd %d",
            inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), client_fd);

        if (handle_accept(client_fd, sin) == false) {
            _log->info("rejecting connection from %s:%d on fd %d",
                inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), client_fd);
            close_socket(client_fd);
            return true;
        }

        ProxyReceiver *receiver = create_proxy_receiver(client_fd, sin, _inbufsz);

        if (receiver == NULL) {
            _log->error("failed to create ProxyReceiver for conn. from %s:%d (%s)",
                inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), strerror(errno));
            close_socket(client_fd);
            return true;
        }

        bool is_new = _fd_hash.insert(client_fd, receiver);
        if (!is_new)
            _log->warning("replaced existing connection with fd %d", client_fd);
        return true;
    } else {
        ProxyReceiver *receiver = _fd_hash.find(fd);
        if (receiver == NULL) return false;
        receiver->selected(fd);
        return true;
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(proxyreceiver)
ELEMENT_PROVIDES(proxyserver)
