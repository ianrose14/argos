#ifndef CLICK_GEOFOCUSCHANNEL_HH
#define CLICK_GEOFOCUSCHANNEL_HH
#include <clicknet/wifi.h>
#include <click/element.hh>
#include <click/error.hh>
#include <click/etheraddress.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
GeoFocusChannel()

=s Argos

This element is an alternative channel-focusing implementation that uses
  hard-coded relationships between sniffers instead of inferring them.

Apps define a custom detector module that feeds off the raw tap.  When an event
for a MAC X is detected, pass that packet to GeoFocusChannel which will use
the proxy_handler_write wifioverlay handler to remotely call the set-channel
handler on each remote sniffer that is "near" the current node.  The duration of
the channel lease and the cooldown period are hard-coded at configuration time.

note: might need to re-enabled high/low priority queues in WifiOverlay for
latency purposes.  ONLY DO THIS IF LATENCY IN EVAL LOOKS BAD.

*/

class GeoFocusChannel : public Element {
public:
    GeoFocusChannel();
    ~GeoFocusChannel();

    const char *class_name() const	{ return "GeoFocusChannel"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    Packet *simple_action(Packet*);

private:
    Logger *_log;
    Timestamp _focus_duration;
    Timestamp _focus_cooldown;
    uint8_t _current_focus;
    Timestamp _cooldown_end;
    Vector<IPAddress> _neighbors;
    bool _self_only;

    String _focus_handler_name;
    const Handler *_focus_handler;
    Element *_focus_element;

    String _setchan_handler_name;
    const Handler *_setchan_handler;
    Element *_setchan_element;
    int _priority;

    static IPAddress host2ip(const char*);
    static int get_neighbors(const String*, Vector<IPAddress>*);
};

CLICK_ENDDECLS
#endif
