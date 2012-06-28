#ifndef CLICK_WIFIEVENTSIM_HH
#define CLICK_WIFIEVENTSIM_HH
#include <click/element.hh>
#include <click/etheraddress.hh>

CLICK_DECLS

/*
=title WifiEventSim

=c

WifiEventSim()

*/

class WifiEventSim : public Element {
public:
    WifiEventSim();
    ~WifiEventSim();

    const char *class_name() const	{ return "WifiEventSim"; }
    const char *port_count() const	{ return "1/1"; }

    void add_handlers();
    int configure(Vector<String> &, ErrorHandler *);
    Packet *simple_action(Packet*);

private:
    Packet *mark_event_packet(Packet *) const;
    static String read_handler(Element*, void*);

    bool _event_enabled;
    Timestamp _event_start, _event_stop;
    Timestamp _event_delay, _event_duration;
    uint8_t _event_channel;
    EtherAddress _event_source;
};

CLICK_ENDDECLS
#endif
