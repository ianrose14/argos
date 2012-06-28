/*
 * networkproxyserver.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "networkproxyserver.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "../argos/net_proto.h"
CLICK_DECLS


NetworkProxyServer::NetworkProxyServer()
    : _server(this), _port(ARGOS_NET_DEF_SERVER_PORT), _log(NULL)
{
}

NetworkProxyServer::~NetworkProxyServer()
{
    if (_log != NULL) delete _log;
}

enum { H_COUNT, H_BYTE_COUNT, H_AVG_CPU, H_AVG_CHILD_CPU, H_PORT,
       H_RESET, H_RESET_AVGS, H_STOP_ACCEPTING };

void
NetworkProxyServer::add_handlers()
{
    add_read_handler("count", read_handler, (void*)H_COUNT);
    add_read_handler("byte_count", read_handler, (void*)H_BYTE_COUNT);
    add_read_handler("avg_cpu", read_handler, (void*)H_AVG_CPU);
    add_read_handler("avg_child_cpu", read_handler, (void*)H_AVG_CHILD_CPU);
    add_read_handler("port", read_handler, (void*)H_PORT);
    add_write_handler("reset_avgs", write_handler, (void*)H_RESET_AVGS);
    add_write_handler("reset", write_handler, (void*)H_RESET);
    add_write_handler("stop_accepting", write_handler, (void*)H_STOP_ACCEPTING);
}

int
NetworkProxyServer::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";
    uint32_t bufsize = 1024*1024;  /* default: 1 MB */
    uint32_t headroom = Packet::default_headroom;

    if (cp_va_kparse(conf, this, errh,
            "PORT", cpkP, cpTCPPort, &_port,
            "RCVBUF", 0, cpUnsigned, &bufsize,
            "HEADROOM", 0, cpUnsigned, &headroom,
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

    _server.set_bufsize(bufsize);
    _server.set_headroom(headroom);
    _server.set_logger(_log);
    return 0;
}

int
NetworkProxyServer::initialize(ErrorHandler *errh)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char portstr[32];
    snprintf(portstr, sizeof(portstr), "%d", _port);

    int rv = getaddrinfo(NULL, portstr, &hints, &servinfo);
    if (rv != 0)
        return errh->error("getaddrinfo: %s", gai_strerror(rv));

    // if getaddrinfo returns 0, it should return a list of addrinfo structs
    assert(servinfo != NULL);
    assert(servinfo->ai_addrlen <= sizeof(struct sockaddr_in));

    struct sockaddr_in sin = *((struct sockaddr_in*)servinfo->ai_addr);
    freeaddrinfo(servinfo);

    if (_server.listen(&sin) != 0)
        return errh->error("ProxyServer::listen(): %s", strerror(errno));

    return 0;
}

void
NetworkProxyServer::selected(int fd)
{
    if (_server.selected(fd) == false)
        _log->critical("selected() called for unknown fd %d", fd);
}

int
NetworkProxyServer::stop_accepting_handler(const String &, ErrorHandler *)
{
    _log->info("'stop accepting' request received");
    _server.stop_listening();
    return 0;
}

String
NetworkProxyServer::read_handler(Element *e, void *thunk)
{
    const NetworkProxyServer *elt = static_cast<NetworkProxyServer *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);

    Vector<ProxyReceiver*> receivers;
    elt->_server.get_connections(&receivers);

    uint32_t count = 0, byte_count = 0;
    for (int i=0; i < receivers.size(); i++) {
        count += receivers[i]->pkt_count();
        byte_count += receivers[i]->byte_count();
    }

    switch (which) {
    case H_COUNT:
        return String(count);
    case H_BYTE_COUNT:
        return String(byte_count);
    case H_AVG_CPU: {
        double elapsed = (Timestamp::now() - elt->_server.start_cpu_time()).doubleval();
        if (elapsed == 0)
            return String("0");
        char cbuf[32];
        Timestamp self_cpu = elt->_server.total_cpu_time() - elt->_server.child_cpu_time();
        double ratio = self_cpu.doubleval() / elapsed;
        snprintf(cbuf, sizeof(cbuf), "%.4f", ratio);
        return String(cbuf);
    }
    case H_AVG_CHILD_CPU: {
        double elapsed = (Timestamp::now() - elt->_server.start_cpu_time()).doubleval();
        if (elapsed == 0)
            return String("0");
        char cbuf[32];
        double ratio = elt->_server.child_cpu_time().doubleval() / elapsed;
        snprintf(cbuf, sizeof(cbuf), "%.4f", ratio);
        return String(cbuf);
    }
    case H_PORT:
        return String((int)elt->_port);
    default:
        return "internal error (bad thunk value)";
    }
}

int
NetworkProxyServer::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    NetworkProxyServer *elt = static_cast<NetworkProxyServer *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET: {
        Vector<ProxyReceiver*> receivers;
        elt->_server.get_connections(&receivers);
        for (int i=0; i < receivers.size(); i++)
            receivers[i]->reset_counts();
        return 0;
    }
    case H_STOP_ACCEPTING:
        return elt->stop_accepting_handler(s_in, errh);
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(proxyreceiver proxyserver userlevel)
EXPORT_ELEMENT(NetworkProxyServer)
