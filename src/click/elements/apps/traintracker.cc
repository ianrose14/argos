/*
 * traintracker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "traintracker.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/etheraddress.hh>
#include <clicknet/wifi.h>
#include "../wifiutil.hh"
CLICK_DECLS

TrainTracker::TrainTracker()
    : _log(NULL)
{
}

TrainTracker::~TrainTracker()
{
    if (_log != NULL) delete _log;
}

int
TrainTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
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

    return 0;
}

int
TrainTracker::initialize(ErrorHandler *)
{
    // NOTE - none of these are currently used
    /*
    _inbound_trains.push_back(7*60 + 3);  // 7:03am
    _inbound_trains.push_back(7*60 + 30);  // 7:30am
    _inbound_trains.push_back(7*60 + 47);  // 7:47am
    _inbound_trains.push_back(8*60 + 11);  // 8:11am
    _inbound_trains.push_back(8*60 + 40);  // 8:40am
    _inbound_trains.push_back(9*60 + 18);  // 9:18am
    _inbound_trains.push_back(10*60 + 4);  // 10:04am
    _inbound_trains.push_back(11*60 + 41);  // 11:41am
    _inbound_trains.push_back(12*60 + 36);  // 12:36pm
    _inbound_trains.push_back(14*60 + 19);  // 2:19pm
    _inbound_trains.push_back(16*60 + 19);  // 4:19pm
    _inbound_trains.push_back(16*60 + 56);  // 4:56pm
    _inbound_trains.push_back(17*60 + 51);  // 5:51pm
    _inbound_trains.push_back(19*60 + 48);  // 7:48pm
    _inbound_trains.push_back(20*60 + 36);  // 8:36pm
    _inbound_trains.push_back(21*60 + 36);  // 9:36pm
    _inbound_trains.push_back(23*60 + 34);  // 11:34pm

    _outbound_trains.push_back(7*60 + 39);  // 7:39am
    _outbound_trains.push_back(8*60 + 30);  // 8:30am
    _outbound_trains.push_back(9*60 + 7);  // 9:07am
    _outbound_trains.push_back(9*60 + 52);  // 9:52am
    _outbound_trains.push_back(11*60 + 32);  // 11:32am
    _outbound_trains.push_back(13*60 + 32);  // 1:32pm
    _outbound_trains.push_back(15*60 + 12);  // 3:12pm
    _outbound_trains.push_back(16*60 + 12);  // 4:12pm
    _outbound_trains.push_back(16*60 + 52);  // 4:52pm
    _outbound_trains.push_back(17*60 + 2);  // 5:02pm
    _outbound_trains.push_back(17*60 + 32);  // 5:32pm
    _outbound_trains.push_back(17*60 + 52);  // 5:52pm
    _outbound_trains.push_back(18*60 + 32);  // 6:32pm
    _outbound_trains.push_back(19*60 + 48);  // 7:48pm
    _outbound_trains.push_back(20*60 + 57);  // 8:57pm
    _outbound_trains.push_back(22*60 + 52);  // 10:52pm
    _outbound_trains.push_back(24*60 + 22);  // 12:22pm
    */
    return 0;
}

Packet *
TrainTracker::simple_action(Packet *p)
{
    const u_char *ta = NULL, *ba = NULL;
    if (wifi_extract_addrs(p->data(), p->length(), NULL, &ta, NULL, NULL, &ba) == -1) {
        // bad frame
        checked_output_push(1, p);
        return NULL;
    }

    EtherAddress bssid;
    if (ba != NULL) bssid = EtherAddress(ba);

    if (ba != NULL) {
        // look for beacons that might tell us about a new train AP
        const struct click_wifi *wifi = (const struct click_wifi *)p->data();
        uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
        uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

        if ((type == WIFI_FC0_TYPE_MGT) && (subtype == WIFI_FC0_SUBTYPE_BEACON)) {
            String ssid;
            if (!wifi_parse_ssid(p->data(), p->length(), &ssid)) {
                // frame truncated or malformed
                checked_output_push(1, p);
                return NULL;
            }

            // if the ssid starts with either "MBTA" or "Coach" we assume that
            // this is a train
            if (ssid.starts_with("MBTA") || ssid.starts_with("Coach")) {
                if (_train_aps.findp(bssid) == NULL) {
                    _train_aps.insert(bssid, ssid);
                    _log->data("NEW-BSS bssid=%s ssid=%s",
                        bssid.unparse_colon().c_str(),
                        wifi_escape_ssid(ssid).c_str());
                }
            }
        }
    }

    // now decide whether or not to emit the packet by checking if the BSSID or
    // transmitter address is the BSSID of a known train
    
    // prefer to match on the BSSID, but if that doesn't work then try the
    // transmitter address (the BSSID could be FF:FF:FF:FF:FF:FF, for example)
    if ((ba != NULL) && (_train_aps.findp(bssid) != NULL))
        return p;

    if ((ta != NULL) && (_train_aps.findp(EtherAddress(ta)) != NULL))
        return p;

    // else, the frame sender is not someone that we know of
    checked_output_push(1, p);
    return NULL;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TrainTracker)
