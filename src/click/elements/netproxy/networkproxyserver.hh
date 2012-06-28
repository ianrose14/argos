#ifndef CLICK_NETWORKPROXYSERVER_HH
#define CLICK_NETWORKPROXYSERVER_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include "proxyreceiver.hh"
#include "proxyserver.hh"
#include "../loghandler.hh"
CLICK_DECLS

/*
=c

NetworkProxyserver()

*/

class NetworkProxyServer : public Element {
public:
    NetworkProxyServer();
    ~NetworkProxyServer();

    const char *class_name() const	{ return "NetworkProxyServer"; }
    const char *port_count() const	{ return PORTS_0_1; }
    const char *processing() const      { return PUSH; }

    // Element methods
    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void selected(int);

private:
    int stop_accepting_handler(const String&, ErrorHandler*);

    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    ProxyServer _server;
    uint16_t _port;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
