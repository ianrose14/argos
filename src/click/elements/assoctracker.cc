/*
 * assoctracker.{cc,hh} -- pretty-print Argos stats messages
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "assoctracker.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include "setsniffer.hh"
#include "wifiutil.hh"
CLICK_DECLS

AssocTracker::AssocTracker()
    : _timer(this), _interval(15), _timeout(300), _dupe_rate(60),
      _ap_to_station_timeout(60), _tx_to_rx_timeout(60),
      _db(NULL), _log(NULL)
{
}

AssocTracker::~AssocTracker()
{
    if (_log != NULL) delete _log;
}

enum { H_DUMP_ALL, H_CLIENT_COUNT, H_INFRA_AP_COUNT, H_IBSS_AP_COUNT,
       H_STATION_COUNT };

void
AssocTracker::add_handlers()
{
    set_handler("query", Handler::OP_READ | Handler::READ_PARAM, query_handler);
    add_read_handler("dump_all", read_handler, (void*)H_DUMP_ALL);

    // count of active clients (infrastructure-mode only)
    add_read_handler("client_count", read_handler, (void*)H_CLIENT_COUNT);

    // count of active APs (infrastructure-mode only)
    add_read_handler("infra_ap_count", read_handler, (void*)H_INFRA_AP_COUNT);

    // count of active IBSS stations
    add_read_handler("ibss_ap_count", read_handler, (void*)H_IBSS_AP_COUNT);

    // count of all active stations
    add_read_handler("station_count", read_handler, (void*)H_STATION_COUNT);
}

void *
AssocTracker::cast(const char *n)
{
    if (strcmp(n, "AssocTracker") == 0)
        return (AssocTracker *)this;
    else
        return 0;
}

int
AssocTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "TIMEOUT", 0, cpTimestamp, &_timeout,
            "INTERVAL", 0, cpTimestamp, &_interval,
            "DB", 0, cpElement, &elt,
            "LOGGING", 0, cpString, &loglevel,
            "NETLOG", 0, cpString, &netlog,
            "LOGGER", 0, cpString, &logelt,
            cpEnd) < 0)
        return -1;

    // create log before anything else
    _log = LogHandler::get_logger(this, NULL, loglevel.c_str(), netlog.c_str(),
        logelt.c_str(), errh);
    if (_log == NULL)
        return -EINVAL;

    // check that elt is a pointer to a PostgreSQL element (if specified at all)
    if (elt != NULL) {
        _db = (PostgreSQL*)elt->cast("PostgreSQL");
        if (_db == NULL)
            return errh->error("DB element is not an instance of type PostgreSQL");
    }

    return 0;
}

int
AssocTracker::initialize(ErrorHandler *)
{
    if (_interval > Timestamp(0,0)) {
        _timer.initialize(this);
        _timer.schedule_after(_interval);
    }
    return 0;
}

Packet *
AssocTracker::simple_action(Packet *p)
{
    const struct click_wifi *wifi = (const struct click_wifi *)p->data();
    
    // all data frames should at least have all of the fields in the click_wifi
    // struct
    if (p->length() < sizeof(struct click_wifi))
        return p;

    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
    uint8_t dir = wifi->i_fc[1] & WIFI_FC1_DIR_MASK;

    // we only care about non-null data frames
    if (type != WIFI_FC0_TYPE_DATA)
        return p;

    if (subtype & WIFI_FC0_SUBTYPE_NODATA)
        return p;

    const u_char *ta = NULL, *ra = NULL, *bssid = NULL;
    if (wifi_extract_addrs(p->data(), p->length(), NULL, &ta, NULL, &ra, &bssid) == -1)
        return p;

    // should never happen (data frames should always have transmitter and
    // receiver addresses)
    if ((ta == NULL) || (ra == NULL))
        return p;

    // do not update associations if the receiver address is a
    // broadcast/multicast address
    if (ra[0] & 0x1)
        return p;

    // BSSID address should always be present except in WDS frames
    if (bssid == NULL)
        return p;

    // transmitter address should never be a broadcast/multicast address
    if (ta[0] & 0x1)
        return p;

    EtherAddress tx_addr = EtherAddress(ta);
    EtherAddress rx_addr = EtherAddress(ra);
    EtherAddress bssid_addr = EtherAddress(bssid);

    // if BSSID is the broadcast address, ignore this frame
    if (bssid_addr.is_broadcast())
        return p;

    bool tx_updated = update_association(tx_addr, bssid_addr, p->timestamp_anno(),
        (dir == WIFI_FC1_DIR_FROMDS), (dir == WIFI_FC1_DIR_NODS), true);

    bool rx_updated = update_association(rx_addr, bssid_addr, p->timestamp_anno(),
        (dir == WIFI_FC1_DIR_TODS), (dir == WIFI_FC1_DIR_NODS), false);

    if (tx_updated)
        _log->data("UPDATE station=%s bssid=%s type=tx",
            tx_addr.unparse_colon().c_str(), bssid_addr.unparse_colon().c_str());

    if (rx_updated)
        _log->data("UPDATE station=%s bssid=%s type=rx",
            rx_addr.unparse_colon().c_str(), bssid_addr.unparse_colon().c_str());

    if (_db != NULL) {
        StoredErrorHandler errh;
        int32_t sniffer_id;
        if (SetSniffer::parse_sniffer_id(p, &sniffer_id, &errh) != 0) {
            _log->error("parse_sniffer_id failed: %s", errh.get_last_error().c_str());
            sniffer_id = 0;
        }

        if (tx_updated)
            db_insert(p->timestamp_anno(), tx_addr, bssid_addr, sniffer_id);

        if (rx_updated)
            db_insert(p->timestamp_anno(), rx_addr, bssid_addr, sniffer_id);
    }

    if (tx_updated || rx_updated) {
        if (noutputs() > 1) {
            Packet *q = p->clone();
            if (q) output(1).push(q);
        }
    }

    return p;
}

void
AssocTracker::run_timer(Timer *)
{
    // erase all associations with a last-updated time prior to 'min_ts'
    _timer.reschedule_after(_interval);
    Timestamp min_ts = Timestamp::now() - _timeout;

    HashMap<EtherAddress, AssocInfo>::iterator iter = _bss_assocs.begin();
    for (; iter != _bss_assocs.end(); iter++) {
        if (iter.value().last_updated <= min_ts) {
            _log->debug("expired %s -> %s%s%s",
                iter.key().unparse_colon().c_str(),
                iter.value().bssid.unparse_colon().c_str(),
                (iter.value().is_ap ? " (AP)" : ""),
                (iter.value().is_ibss ? " (ibss)" : ""));
            bool deleted = _bss_assocs.erase(iter.key());
            assert(deleted == true);
        }
    }
}

/*
 * PRIVATE METHODS
 */

void
AssocTracker::db_insert(const Timestamp &ts, const EtherAddress &station,
    const EtherAddress &bssid, int32_t node_id)
{
   Vector<const char*> values;

   // note: uses capt_node_id exclusively
   static const String query = String("INSERT INTO wifi_associations"
        " (timestamp, station_mac, bssid, capt_node_id)"
        " VALUES"
        " (timestamptz 'epoch' + $1 * interval '1 second', $2, $3, $4);");

    String ts_str = ts.unparse();
    String station_str = station.unparse_colon();
    String bssid_str = bssid.unparse_colon();
    String node_id_str = String(node_id);

    values.push_back(ts_str.c_str());
    values.push_back(station_str.c_str());
    values.push_back(bssid_str.c_str());
    values.push_back(node_id_str.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0)
        _log->error("db_insert failed: %s", errh.get_last_error().c_str());
    else if (rv == 1)
        _log->debug("1 row inserted for station %d, node_id %d", station_str.c_str(),
            node_id);
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for station %s, node_id %d", rv,
            station_str.c_str(), node_id);
}

uint32_t
AssocTracker::get_station_count(bool aps, bool clients, bool ibss) const
{
    uint32_t count = 0;
    HashMap<EtherAddress, AssocInfo>::const_iterator iter = _bss_assocs.begin();
    for (; iter != _bss_assocs.end(); iter++) {
        if (iter.value().is_ibss) {
            if (ibss) count++;
        }
        else {
            // !iter.value().is_ibss
            if (aps && iter.value().is_ap)
                count++;
            if (clients && (!iter.value().is_ap))
                count++;
        }
    }
    return count;
}

bool
AssocTracker::infer_bssid(const Packet *p, EtherAddress *bssid) const
{
    const uint8_t *mac_ptr;
    if (p->has_mac_header())
        mac_ptr = p->mac_header();
    else
        mac_ptr = p->data();

    size_t frame_len = p->end_data() - mac_ptr;

    const u_char *sa = NULL, *da = NULL, *ba = NULL;
    if (wifi_extract_addrs(mac_ptr, frame_len, &sa, NULL, &da, NULL, &ba) == -1)
        return false;

    // if we got a BSSID, use that
    if (ba != NULL) {
        *bssid = EtherAddress(ba);
        return true;
    }

    // otherwise, if we got a source address, try to look up that station to get
    // its BSSID
    if (sa != NULL) {
        EtherAddress src = EtherAddress(sa);
        if (lookup_station(src, bssid))
            return true;
    }

    // lastly, if we got a destination address, try to look up that station to
    // get its BSSID
    if (da != NULL) {
        EtherAddress dst = EtherAddress(da);
        if (lookup_station(dst, bssid))
            return true;
    }

    // nothing worked - we have no way to infer this packet's BSSID
    return false;
}

bool
AssocTracker::lookup_station(EtherAddress &sta, EtherAddress *bssid) const
{
    AssocInfo *info = _bss_assocs.findp(sta);
    if (info == NULL)
        return false;

    *bssid = info->bssid;
    return true;
}

bool
AssocTracker::update_association(EtherAddress &station, EtherAddress &bssid,
    Timestamp &ts, bool is_ap, bool is_ibss, bool as_tx)
{
    AssocInfo *ai = _bss_assocs.findp(station);
    if (ai == NULL) {
        AssocInfo new_ai = AssocInfo();
        new_ai.bssid = bssid;
        new_ai.is_ibss = is_ibss;
        new_ai.is_ap = is_ap;
        new_ai.last_updated = ts;
        new_ai.last_duped = ts;
        new_ai.last_tx = (as_tx ? ts : Timestamp(0));
        _bss_assocs.insert(station, new_ai);

        _log->debug("inserted %s -> %s%s%s (as %s)", station.unparse_colon().c_str(),
            bssid.unparse_colon().c_str(), (is_ap ? " (AP)" : ""),
            (is_ibss ? " (ibss)" : ""), (as_tx ? "tx" : "rx"));

        // always push a packet-duplicate when a new association is detected
        return true;
    } else {
        // confirm that new BSSID matches old BSSID
        if (bssid != ai->bssid) {
            // this client's association appears to have changed so update the
            // mapping and push a duplicate of this packet

            // special case!  I have seen a rare situation where a (seemingly)
            // single device exposed 2 different BSSIDS (OUIs were E0:CB:4E and
            // 00:24:8C, both belonging to ASUS), although both advertised the
            // same SSID ("Eric").  What makes this particularly odd is that
            // occasionally I will capture packets (TCP, UDP and ARP) with the
            // wifi source and destination addrs equal to the two BSSIDs; the
            // wifi BSSID field is set to one of the two - one seems to
            // predominate, but I have seen both used.  I even saw a case where
            // two adjacent packets from the same TCP stream (identical
            // 5-tuples) used the same SRC and DST addrs, but flipped the BSSID
            // field.  So how do we deal with this?  If the station already
            // exists in the table *as an AP*, then we require at least
            // _ap_to_station_timeout seconds to pass since the last update.
            if (ai->is_ap) {
                if (ts <= (ai->last_updated + _ap_to_station_timeout)) {
                    // not ok to update yet
                    return false;
                }
            }

            // updating a node association based on a *receiver* address is a
            // little bit sketchy; its much better to update associations based
            // on transmitter addresses.  So we require a timeout period of no
            // tx-association updates before an rx-association update will be
            // allowed.
            if (ts >= (ai->last_tx + _tx_to_rx_timeout)) {
                // not ok to update yet
                return false;
            }

            _log->debug("updated %s from %s%s%s to %s%s%s (as %s)",
                station.unparse_colon().c_str(), ai->bssid.unparse_colon().c_str(),
                (ai->is_ap ? " (AP)" : ""), (ai->is_ibss ? " (ibss)" : ""),
                bssid.unparse_colon().c_str(), (is_ap ? " (AP)" : ""),
                (is_ibss ? " (ibss)" : ""), (as_tx ? "tx" : "rs"));

            ai->bssid = bssid;
            ai->is_ibss = is_ibss;
            ai->is_ap = is_ap;
            ai->last_duped = ts;
            ai->last_updated = ts;
            if (as_tx) ai->last_tx = ts;
            return true;
        } else {
            ai->last_updated = ts;

            // push a packet-duplicate only if the last dupe time for this
            // association was more than _dupe_rate ago
            if (ai->last_duped <= (ts - _dupe_rate)) {
                ai->last_duped = ts;
                return true;
            } else
                return false;
        }
    }
}


/*
 * STATIC METHODS
 */

int
AssocTracker::query_handler(int, String &s, Element *e, const Handler*, ErrorHandler *errh)
{
    AssocTracker *elt = static_cast<AssocTracker*>(e);
    EtherAddress ether, bssid;
    if (cp_ethernet_address(s, &ether, elt)) {
        if (elt->lookup_station(ether, &bssid))
            s = bssid.unparse_colon();
        else
            s = "";
        return 0;
    } else
        return errh->error("expected Ethernet address, not '%s'", s.c_str());
}

String
AssocTracker::read_handler(Element *e, void *thunk)
{
    const AssocTracker *elt = static_cast<AssocTracker *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_CLIENT_COUNT:
        return String(elt->get_station_count(false, true, false));
    case H_INFRA_AP_COUNT:
        return String(elt->get_station_count(true, false, false));
    case H_IBSS_AP_COUNT:
        return String(elt->get_station_count(false, false, true));
    case H_STATION_COUNT:
        return String(elt->get_station_count(true, true, true));
    case H_DUMP_ALL: {
        StringAccum sa;
        HashMap<EtherAddress, AssocInfo>::const_iterator iter = elt->_bss_assocs.begin();
        for (; iter != elt->_bss_assocs.end(); iter++) {
            sa << iter.key().unparse_colon() << " -> "
               << iter.value().bssid.unparse_colon();
            if (iter.value().is_ibss)
                sa << " (ibss)";
            else if (iter.value().is_ap)
                sa << " (AP)";
            else
                sa << " (station)";
            sa << "\n";
        }
        
        return sa.take_string();
    }
    default:
        return "internal error (bad thunk value)";
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(AssocTracker)
