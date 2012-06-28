#ifndef CLICK_GUESSCHANNEL_HH
#define CLICK_GUESSCHANNEL_HH
#include <click/element.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include "../assoctracker.hh"
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
GuessChannel()

=s Argos

Makes a guess at what channel each packet was sent on, and stores that value in
the Argos annotation area.

=d
Makes a guess at what channel each packet was sent on, and stores that value in
the Argos annotation area.

*/

class GuessChannel : public Element {
public:
    GuessChannel();
    ~GuessChannel();

    const char *class_name() const	{ return "GuessChannel"; }
    const char *port_count() const	{ return PORTS_1_1; }

    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void run_timer(Timer*);
    Packet *simple_action(Packet*);

private:
    uint8_t estimate_channel(const Packet*);
    void update_channel_cache(const Packet*);

    struct APInfo {
        Timestamp last_updated;
        uint8_t channel;
        APInfo() {};
        APInfo(Timestamp ts, uint8_t chan) : last_updated(ts), channel(chan) {};
        APInfo(uint8_t chan) : last_updated(Timestamp::now()), channel(chan) {};
        ~APInfo() {};
    };

    Timer _timer;
    HashMap<EtherAddress, APInfo> _ap_channel_cache;
    Timestamp _timeout;
    Timestamp _gc_interval;

    // used to track client->BSSID associations
    const AssocTracker *_assoc_tracker;

    Logger *_log;
};

CLICK_ENDDECLS
#endif
