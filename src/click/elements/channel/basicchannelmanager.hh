#ifndef CLICK_BASICCHANNELMANAGER_HH
#define CLICK_BASICCHANNELMANAGER_HH
#include <click/dequeue.hh>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/list.hh>
#include <click/timer.hh>
#include <click/timestamp.hh>
#include "wifichannel.hh"
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
BasicChannelManager()

=s Argos

Arbitrates access to sniffers' channels.

=d
Arbitrates access to sniffers' channels.
*/

class BasicChannelManager : public Element {
public:
    BasicChannelManager();
    ~BasicChannelManager();

    const char *class_name() const      { return "BasicChannelManager"; }
    const char *flags() const           { return "S0"; }
    const char *port_count() const      { return PORTS_1_1; }
    const char *processing() const      { return AGNOSTIC; }

    void add_handlers();
    int configure(Vector<String> &, ErrorHandler*);
    int initialize(ErrorHandler *);
    Packet *simple_action(Packet *);

private:
    int cancel_lease_handler(const String&, ErrorHandler*);
    bool change_channel(uint8_t);
    int get_channel();
    int lease_channel_handler(const String&, ErrorHandler*);
    void reset_stats();

    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    bool _active;

    String _getchan_handler_name;
    Element *_getchan_element;
    const Handler *_getchan_handler;
    String _setchan_handler_name;
    Element *_setchan_element;
    const Handler *_setchan_handler;

    struct ChannelChange {
        Timestamp start_ts, end_ts;
        uint8_t channel;
    };

    Vector<ChannelChange> _history;
    int _max_history;

    uint8_t _current_channel;
    String _current_lease_owner;
    uint8_t _current_lease_priority;   // 255 if no current lease
    Timestamp _current_lease_end;
    uint16_t _current_lease_key;  // used for cancelling the lease

    // last time that channel

    // amount of time spent on each channel (for stats only)
    Timestamp _channel_durations[MAX_80211_CHANNEL];
    Timestamp _last_durations_update;

    Logger *_log;
};

CLICK_ENDDECLS
#endif
