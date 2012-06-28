/*
 * proberequesttracker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "proberequesttracker.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include "../setsniffer.hh"
#include "../wifiutil.hh"
CLICK_DECLS


ProbeRequestTracker::ProbeRequestTracker()
    : _ignore_null_ssid(true), _dupe_window(0), _db(NULL), _log(NULL)
{
}

ProbeRequestTracker::~ProbeRequestTracker()
{
    if (_log != NULL) delete _log;
}

int
ProbeRequestTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "IGNORE_NULL_SSID", 0, cpBool, &_ignore_null_ssid,
            "DUPE_WINDOW", 0, cpTimestamp, &_dupe_window,
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

void
ProbeRequestTracker::push(int, Packet *p)
{
    const struct click_wifi *wifi = (const struct click_wifi *)p->data();

    // we don't care about control frames, and all others (data and management
    // frames) should at least have all of the fields in the click_wifi struct
    if (p->length() < sizeof(struct click_wifi)) {
        p->kill();
        return;
    }

    // look for probe-requests only
    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    if ((type != WIFI_FC0_TYPE_MGT) || (subtype != WIFI_FC0_SUBTYPE_PROBE_REQ)) {
        p->kill();
        return;
    }

    // in all ProbeRequest frames, addr2 = SRC and addr3 = BSSID
    EtherAddress src = EtherAddress(wifi->i_addr2);
    EtherAddress bssid = EtherAddress(wifi->i_addr3);

    String ssid;
    if (!wifi_parse_ssid(p->data(), p->length(), &ssid)) {
        // packet truncated or malformed
        _log->debug("rejecting ProbeReq from %s (no SSID element)",
            src.unparse_colon().c_str());
        p->kill();
        return;
    }

    if (_ignore_null_ssid && (ssid.length() == 0)) {
        p->kill();
        return;
    }

    if (_dupe_window != Timestamp(0)) {
        ProbeRequestKey key = ProbeRequestKey(src, bssid, ssid);
        Timestamp *prev_ts = _recent_probereqs.findp(key);
        if (prev_ts != NULL) {
            // elapsed could be negative!
            Timestamp elapsed = p->timestamp_anno() - *prev_ts;
            if (elapsed <= _dupe_window) {
                _log->debug("rejecting ProbeReq from %s; recent dupe (%s ago) to SSID %s",
                    src.unparse_colon().c_str(), elapsed.unparse().c_str(),
                    wifi_escape_ssid(ssid).c_str());
                p->kill();
                return;
            }
        }
    }

    StoredErrorHandler errh;
    int32_t sniffer_id;
    if (SetSniffer::parse_sniffer_id(p, &sniffer_id, &errh) != 0) {
        _log->error("parse_sniffer_id failed: %s", errh.get_last_error().c_str());
        sniffer_id = 0;
    }

    _log->data("PROBE-REQ src=%s ssid=\"%s\" bssid=%s", src.unparse_colon().c_str(),
        wifi_escape_ssid(ssid).c_str(), bssid.unparse_colon().c_str());

    if (_db) db_insert(p->timestamp_anno(), src, bssid, ssid, sniffer_id);

    if (_dupe_window != Timestamp(0)) {
        ProbeRequestKey key = ProbeRequestKey(src, bssid, ssid);
        _recent_probereqs.insert(key, p->timestamp_anno());
    }

    output(0).push(p);
}

void
ProbeRequestTracker::db_insert(const Timestamp &ts, const EtherAddress &src,
    const EtherAddress &bssid, const String &ssid, int32_t node_id)
{
    Vector<const char*> values;

    // note: uses capt_node_id exclusively
    static const String query = String("INSERT INTO wifi_probe_requests"
        " (timestamp, src_mac, bssid, ssid, capt_node_id)"
        " VALUES"
        " (timestamptz 'epoch' + $1 * interval '1 second', $2, $3, $4, $5);");

    String ts_str = ts.unparse();
    String src_str = src.unparse_colon();
    String bssid_str = bssid.unparse_colon();
    String node_id_str = String(node_id);

    values.push_back(ts_str.c_str());
    values.push_back(src_str.c_str());
    values.push_back(bssid_str.c_str());
    values.push_back(ssid.c_str());
    values.push_back(node_id_str.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0)
        _log->error("db_insert failed: %s", errh.get_last_error().c_str());
    else if (rv == 1)
        _log->debug("1 row inserted for src %d, node_id %d", src_str.c_str(),
            node_id);
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for src %s, node_id %d", rv,
            src_str.c_str(), node_id);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ProbeRequestTracker)
