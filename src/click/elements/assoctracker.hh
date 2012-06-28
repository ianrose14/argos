#ifndef CLICK_ASSOCTRACKER_HH
#define CLICK_ASSOCTRACKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "loghandler.hh"
#include "db/postgresql.hh"
CLICK_DECLS

/*
=c
AssocTracker()

*/

class AssocTracker : public Element {
public:
    AssocTracker();
    ~AssocTracker();

    const char *class_name() const	{ return "AssocTracker"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PUSH; }

    void add_handlers();
    void *cast(const char *);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    Packet *simple_action(Packet*);
    void run_timer(Timer*);

    uint32_t get_station_count(bool, bool, bool) const;
    bool infer_bssid(const Packet*, EtherAddress*) const;
    bool lookup_station(EtherAddress&, EtherAddress*) const;

private:
    void db_insert(const Timestamp&, const EtherAddress&, const EtherAddress&, int32_t);
    static int query_handler(int, String&, Element*, const Handler*, ErrorHandler*);
    static String read_handler(Element*, void *);
    bool update_association(EtherAddress&, EtherAddress&, Timestamp&, bool, bool, bool);

    struct AssocInfo {
        EtherAddress bssid;
        bool is_ibss;
        bool is_ap;  // is the MAC address that keys this object an AP or a client?
        Timestamp last_updated;
        Timestamp last_duped;  // meaningful only when noutputs() > 1
        Timestamp last_tx;
    };

    HashMap<EtherAddress, AssocInfo> _bss_assocs;

    Timer _timer;
    Timestamp _interval;
    Timestamp _timeout;
    Timestamp _dupe_rate;

    // for some AP X, the amount of time that must pass since the last packet
    // identifying X as an AP before X can be updated to be a client (see
    // comments in simple_action)
    Timestamp _ap_to_station_timeout;

    // for some station X, the amount of time that must pass since the last
    // packet identifying X *as a transmitter* before X can be updated *as a
    // receiver* to a different BSSID
    Timestamp _tx_to_rx_timeout;

    bool _verbose;
    PostgreSQL *_db;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
