#ifndef CLICK_BSSTRACKER_HH
#define CLICK_BSSTRACKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS

/*
=c
BSSTracker()

*/

class BSSTracker : public Element {
public:
    BSSTracker();
    ~BSSTracker();

    const char *class_name() const	{ return "BSSTracker"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PUSH; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet*);

private:
    struct BSSInfo {
        String ssid;
        bool is_ibss, ssid_changed, ssid_in_beacons;
        int channels;  // bitmask of advertised channels
        int bcn_int;
        int encryption_types;  // unicast cipher + key-management
        int group_cipher;
    };

    void db_insert_bss(EtherAddress&, BSSInfo*);
    void db_update_bss(EtherAddress&, BSSInfo*);
    static String read_handler(Element*, void*);

    // map from BSSID to BSSInfo structure
    HashMap<EtherAddress, BSSInfo> _bss_map;

    PostgreSQL *_db;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
