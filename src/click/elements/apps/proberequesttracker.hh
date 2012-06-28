#ifndef CLICK_PROBEREQUESTTRACKER_HH
#define CLICK_PROBEREQUESTTRACKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/glue.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS

/*
=c
ProbeRequestTracker()

*/

class ProbeRequestKey;

class ProbeRequestTracker : public Element {
public:
    ProbeRequestTracker();
    ~ProbeRequestTracker();

    const char *class_name() const	{ return "ProbeRequestTracker"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);
    void push(int, Packet*);

private:
    void db_insert(const Timestamp&, const EtherAddress&, const EtherAddress&,
        const String&, int32_t);

    bool _ignore_null_ssid;
    Timestamp _dupe_window;
    HashMap<ProbeRequestKey, Timestamp> _recent_probereqs;
    PostgreSQL *_db;
    Logger *_log;
};

class ProbeRequestKey {
public:
    ProbeRequestKey() {}
    ProbeRequestKey(const EtherAddress &_src, const EtherAddress &b, const String &_ssid)
        : src(_src), bssid(b), ssid(_ssid) {}
    ~ProbeRequestKey() {}

    inline size_t hashcode() const { return src.hashcode() ^ bssid.hashcode() ^ ssid.hashcode(); }

    EtherAddress src;
    EtherAddress bssid;
    String ssid;
};

inline bool
operator==(const ProbeRequestKey &a, const ProbeRequestKey &b)
{
    return (a.src == b.src) && (a.bssid == b.bssid) && (a.ssid == b.ssid);
}

CLICK_ENDDECLS
#endif
