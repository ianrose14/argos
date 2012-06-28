#ifndef CLICK_PROXYSERVER_HH
#define CLICK_PROXYSERVER_HH
#include <click/dequeue.hh>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/ipaddress.hh>
#include <click/vector.hh>
#include <unistd.h>
#include "proxyreceiver.hh"
#include "../loghandler.hh"
CLICK_DECLS

/*
=c

ProxyServer()

*/

class ProxyReceiver;

class ProxyServer {
public:
    ProxyServer(Element*);
    ~ProxyServer();

    void close();
    inline void close_socket(int);
    virtual ProxyReceiver *create_proxy_receiver(int, const struct sockaddr_in*, size_t);
    void get_connections(Vector<ProxyReceiver*> *vec) const;
    virtual bool handle_accept(int, const struct sockaddr_in*);
    void handle_close(int);
    virtual void handle_packet(Packet*, const struct sockaddr_in*);
    int listen(const struct sockaddr_in*);
    bool selected(int);
    inline void set_bufsize(size_t size) { _inbufsz = size; }
    inline void set_headroom(uint32_t headroom) { _headroom = headroom; }
    inline void set_logger(Logger *log);
    void stop_listening();
    inline void trace_cpu(bool on) { _trace_cpu = on; _start_cpu_time = Timestamp::now(); }

    inline Timestamp child_cpu_time() const { return _child_cpu_time; }
    inline Timestamp start_cpu_time() const { return _start_cpu_time; }
    inline Timestamp total_cpu_time() const { return _total_cpu_time; }

protected:
    Element *_elt;
    Logger *_log;
    struct sockaddr_in _addr;  // bound address

private:
    bool handle_selected(int);

    int _sock;  // listen()-ing socket
    size_t _inbufsz;  // buffer size used by receivers, not by me
    HashMap<int, ProxyReceiver*> _fd_hash;
    uint32_t _headroom;

    bool _trace_cpu;
    Timestamp _start_cpu_time;
    Timestamp _total_cpu_time;
    Timestamp _child_cpu_time;   // CPU time used during packed pushes
};

void
ProxyServer::close_socket(int fd) {
    while ((::close(fd) == -1) && (errno == EINTR));
}

void
ProxyServer::set_logger(Logger *l)
{
    _log = l->clone("[ProxyServer] ");
}

CLICK_ENDDECLS
#endif
