/*
 * apchanneltracker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "apchanneltracker.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/wifi.h>
#include "../setsniffer.hh"
#include "../wifiutil.hh"
CLICK_DECLS

APChannelTracker::APChannelTracker()
    : _max_logs_per_ap(1500) /* this is enough to notify once per minute */,
      _max_pushes_per_ap(100), _timer(this), _timer_interval(24*60*60, 0),
      _db(NULL), _log(NULL)
{
}

APChannelTracker::~APChannelTracker()
{
    if (_log != NULL) delete _log;
}

int
APChannelTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "AP_MAX_DAILY_LOG", 0, cpUnsigned, &_max_logs_per_ap,
            "AP_MAX_DAILY_PUSH", 0, cpUnsigned, &_max_pushes_per_ap,
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
APChannelTracker::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_after(_timer_interval);
    return 0;
}

void
APChannelTracker::push(int, Packet *p)
{
    const struct click_wifi *wifi = (const struct click_wifi *)p->data();

    // look for beacons and probe responses only
    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    if (type != WIFI_FC0_TYPE_MGT) {
        p->kill();
        return;
    }

    if ((subtype != WIFI_FC0_SUBTYPE_BEACON) && (subtype != WIFI_FC0_SUBTYPE_PROBE_RESP)) {
        p->kill();
        return;
    }

    // in Beacon and ProbeResp frames, addr2 = "SA" and addr3 = "BSSID"
    EtherAddress src = EtherAddress(wifi->i_addr2);
    EtherAddress bssid = EtherAddress(wifi->i_addr3);

    uint8_t elt_len;
    const u_char *elt;
    if (!wifi_parse_infoelt(p->data(), p->length(), WIFI_ELEMID_DSPARMS, &elt_len, &elt)) {
        // frame truncated or malformed, or no "DS Parameter Set" element present
        p->kill();
        return;
    }

    // sanity check
    if (elt_len != 1) {
        _log->warning("packet received with DS-Params InfoElt of length %d", 
            elt_len);
        checked_output_push(1, p);
        return;
    }

    uint8_t channel = elt[0];

    // is this a new AP?  (note we index by MAC-address, not BSSID, although
    // in most, or all, non-IBSS cases these will be identical)
    APInfo *info = _aps.findp(src);

    if (info == NULL) {
        // new AP
        APInfo new_info;
        new_info.bssid = bssid;
        new_info.channel = channel;
        new_info.pkt = p;
        new_info.logs = 1;
        new_info.pushes = 0;

        if (!wifi_parse_ssid(p->data(), p->length(), &new_info.ssid)) {
            // frame truncated or malformed
            p->kill();
            return;
        }

        _aps.insert(src, new_info);

        _log->data("new-AP MAC=%s BSSID=%s CHAN=%d SSID=\"%s\"",
            src.unparse_colon().c_str(), bssid.unparse_colon().c_str(),
            channel, wifi_escape_ssid(new_info.ssid).c_str());
    }
    else {
        if (channel != info->channel) {
            if (info->logs < _max_logs_per_ap) {
                _log->data("channel-change MAC=%s BSSID=%s NEW-CHAN=%d PREV-CHAN=%d",
                    src.unparse_colon().c_str(), bssid.unparse_colon().c_str(),
                    info->channel, channel);

                info->logs++;
            }

            if (_db) {
                // figure out who (sniffer_id) sent this packet, then log it
                StoredErrorHandler errh;
                int32_t sniffer_id;
                if (SetSniffer::parse_sniffer_id(p, &sniffer_id, &errh) != 0) {
                    _log->error("parse_sniffer_id failed: %s", errh.get_last_error().c_str());
                } else {
                    db_insert(p->timestamp_anno(), src, bssid, info->channel,
                        channel, sniffer_id);
                }
            }

            info->channel = channel;

            // push the saved packet (which should advertise the old channel)
            // and then the new packet (which should advertise the new channel)
            if (info->pushes < _max_pushes_per_ap) {
                if (info->pkt != NULL)
                    output(0).push(info->pkt);
                output(0).push(p);

                info->pkt = NULL;
                info->pushes += 2;
                return;
            }
        }

        // update the saved packet
        if (info->pkt != NULL)
            info->pkt->kill();
        info->pkt = p;
    }
}

void
APChannelTracker::run_timer(Timer *)
{
    // reset all APs' logging-counts and push-counts to 0
    HashMap<EtherAddress, APInfo>::iterator iter = _aps.begin();
    for (; iter != _aps.end(); iter++) {
        iter.value().logs = 0;
        iter.value().pushes = 0;
    }

    _timer.reschedule_after(_timer_interval);
}

void
APChannelTracker::db_insert(Timestamp &ts, EtherAddress &src,
    EtherAddress &bssid, uint8_t from_chan, uint8_t to_chan, int32_t node_id)
{
    Vector<const char*> values;

    // note: uses capt_node_id exclusively
    static const String query = String("INSERT INTO wifi_ap_channel_changes"
        " (timestamp, ap, bssid, prev_chan, new_chan, capt_node_id)"
        " VALUES"
        " (timestamptz 'epoch' + $1 * interval '1 second', $2, $3, $4, $5, $6);");

    String ts_str = ts.unparse();
    String src_str = src.unparse_colon();
    String bssid_str = bssid.unparse_colon();
    String from_chan_str = String((int)from_chan);
    String to_chan_str = String((int)to_chan);
    String node_id_str = String(node_id);

    values.push_back(ts_str.c_str());
    values.push_back(src_str.c_str());
    values.push_back(bssid_str.c_str());
    values.push_back(from_chan_str.c_str());
    values.push_back(to_chan_str.c_str());
    values.push_back(node_id_str.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0)
        _log->error("db_insert failed: %s", errh.get_last_error().c_str());
    else if (rv == 1)
        _log->debug("1 row inserted for BSSID %s", bssid.unparse_colon().c_str());
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for BSSID %s", rv,
            bssid.unparse_colon().c_str());
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(APChannelTracker)
