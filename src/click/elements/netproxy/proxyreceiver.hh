#ifndef CLICK_PROXYRECEIVER_HH
#define CLICK_PROXYRECEIVER_HH
#include <click/packet.hh>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "proxyserver.hh"
#include "networkproxy.hh"  // for QLZ macros
#include "../buffer.h"
#include "../loghandler.hh"
#include "../quicklz.h"
CLICK_DECLS

/*
=c

ProxyReceiver()

*/

class ProxyServer;

class ProxyReceiver {
public:
    ProxyReceiver(int, const struct sockaddr_in*, size_t, ProxyServer*);
    ~ProxyReceiver();

    inline const IPAddress address() const { return IPAddress(_addr.sin_addr); }
    inline uint32_t byte_count() const { return _bytes_recv; }
    void close();
    inline uint32_t pkt_count() const { return _pkts_recv; }
    inline void reset_counts() { _bytes_recv = 0; _pkts_recv = 0; }
    void selected(int fd);
    inline void set_headroom(uint32_t headroom) { _headroom = headroom; }
    inline void set_logger(Logger *log);

private:
    bool decompress_packets(uint8_t, const u_char*, uint32_t, u_char*, uint32_t);
    static Packet *deserialize_packet(u_char *, size_t, uint32_t);
    bool process_buffer(struct buffer*);

    int _sock;
    struct sockaddr_in _addr;
    ProxyServer *_server;
    bool _is_closed;
    struct buffer *_inbuf;
    struct buffer *_msgbuf;
    char _qlz_scratch[QLZ_SCRATCH_COMPRESS];
    uint32_t _bytes_recv;
    uint32_t _pkts_recv;

    bool _reported_mem_drop;
    uint32_t _headroom;
    Logger *_log;
};

void
ProxyReceiver::set_logger(Logger *l)
{
    char prefix[256];
    snprintf(prefix, sizeof(prefix), "[ProxyReceiver %s] ", inet_ntoa(_addr.sin_addr));
    _log = l->clone(prefix);
}

CLICK_ENDDECLS
#endif
