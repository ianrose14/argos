#ifndef CLICK_HTTPREQUESTFILTER_HH
#define CLICK_HTTPREQUESTFILTER_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
HttpRequestFilter()

*/

class HttpRequestFilter : public Element {
public:
    HttpRequestFilter();
    ~HttpRequestFilter();

    const char *class_name() const	{ return "HttpRequestFilter"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet*);

private:
    int _dlt;
    bool _verbose;
};

CLICK_ENDDECLS
#endif
