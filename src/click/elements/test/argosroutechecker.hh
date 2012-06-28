#ifndef CLICK_ARGOSROUTECHECKER_HH
#define CLICK_ARGOSROUTECHECKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include "../assoctracker.hh"
#include "../loghandler.hh"
#include "../wifioverlay.hh"
CLICK_DECLS

/*
=c
ArgosRouteChecker()
*/

class ArgosRouteChecker : public Element {
public:
    ArgosRouteChecker();
    ~ArgosRouteChecker();

    const char *class_name() const	{ return "ArgosRouteChecker"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler *);
    Packet *simple_action(Packet*);

private:
    // used to track client->BSSID associations
    const AssocTracker *_assoc_tracker;

    // used to look up the current BSSID->node mappings
    const WifiOverlay *_router;

    Logger *_log;
};

CLICK_ENDDECLS
#endif
