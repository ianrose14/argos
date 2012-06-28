#ifndef CLICK_APCHANNELTRACKER_HH
#define CLICK_APCHANNELTRACKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS

/*
=c
APChannelTracker()

*/

class APChannelTracker : public Element {
public:
    APChannelTracker();
    ~APChannelTracker();

    const char *class_name() const      { return "APChannelTracker"; }
    const char *port_count() const      { return PORTS_1_1X2; }
    const char *processing() const      { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet*);
    void run_timer(Timer*);

private:
    struct APInfo {
        EtherAddress bssid;
        String ssid;
        uint8_t channel;  // what channel the AP last advertised
        Packet *pkt;      // a copy of the beacon advertising that channel
        uint32_t logs;    // number of channel-change messages logged for this AP
        uint32_t pushes;  // number of packets that we have pushed for this AP
    };

    void db_insert(Timestamp&, EtherAddress&, EtherAddress&, uint8_t, uint8_t,
        int32_t);

    HashMap<EtherAddress, APInfo> _aps;

    uint32_t _max_logs_per_ap;  // daily limit
    uint32_t _max_pushes_per_ap;  // daily limit

    Timer _timer;  // used to reset AP push counts every 24 hours
    Timestamp _timer_interval;
    PostgreSQL *_db;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
