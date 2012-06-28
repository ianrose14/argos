/*
 * focuschannel.{cc,hh} -- implements channel focusing
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "focuschannel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include "../argos/anno.h"
#include "../wifiutil.hh"
CLICK_DECLS

/*
NOTE - THIS ELEMENT'S IMPLEMENTATION IS NOT COMPLETE (IT NEEDS SOME HANDLERS)

SEE COMMENTS IN FOCUSCHANNEL.HH
*/


/*
 * SnifferMap Methods
 */

void
SnifferMap::beacon_capture(int beacon_interval, int nelts,
    struct argos_wifimerge_elt *elts)
{
    for (int i=0; i < nelts; i++) {
        IPAddress sniffer = IPAddress(elts[i].src);
        FidelityStats *stats = _sniffer_stats.findp(sniffer);
        if (stats == NULL) {
            _sniffer_stats.insert(sniffer, FidelityStats(beacon_interval));
            stats = _sniffer_stats.findp(sniffer);
            assert(stats != NULL);
        }

        stats->add_capture();
    }

    last_packet = Timestamp::now();
}

void
SnifferMap::get_sniffers(uint32_t thresh_perc, Vector<IPAddress> *sniffers)
{
    HashMap<IPAddress, FidelityStats>::iterator iter = _sniffer_stats.begin();
    for (; iter != _sniffer_stats.end(); iter++) {
        if (iter.value()._rate.unscaled_average() >= thresh_perc)
            sniffers->push_back(iter.key());
    }
}

void
SnifferMap::update(Timestamp *now)
{
    HashMap<IPAddress, FidelityStats>::iterator iter = _sniffer_stats.begin();
    for (; iter != _sniffer_stats.end(); iter++) {
        iter.value().update(now);
    }
}

/*
 * FocusChannel Methods
 */

FocusChannel::FocusChannel()
    : _timer(this), _timeout(300, 0), _interval(1, 0)
{
}

FocusChannel::~FocusChannel()
{
    if (_log != NULL) delete _log;
}

int
FocusChannel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "TIMEOUT", 0, cpSeconds, &_timeout,
            "INTERVAL", 0, cpTimestamp, &_interval,
            "LOGGING", 0, cpTimestamp, &loglevel,
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
FocusChannel::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_after(_interval);
    return 0;
}

void
FocusChannel::run_timer(Timer *)
{
    Timestamp now = Timestamp::now();
    Timestamp thresh = now - _timeout;

    HashMap<EtherAddress, SnifferMap>::iterator iter = _ap_map.begin();
    while (iter != _ap_map.end()) {
        EtherAddress addr;
        bool do_erase = (iter.value().last_packet <= thresh);
        if (do_erase) {
            addr = iter.key();
        } else {
            iter.value().update(&now);
        }

        // make sure to increment iterator before we remove this entry
        iter++;

        // this entry was last packet reception was too long ago; expire it
        if (do_erase) _ap_map.remove(addr);
    }
    _timer.reschedule_after(_interval);
}

Packet *
FocusChannel::simple_action(Packet *p)
{
    // first determine if this is an 802.11 beacon
    if (!p->has_mac_header()) {
        // bad packet
        _log->warning("bad packet received (no mac header pointer)");
        return p;
    }

    const uint8_t *mac_ptr = p->mac_header();

    size_t frame_len = p->end_data() - mac_ptr;
    if (frame_len < sizeof(struct click_wifi))
        return p;  // packet too small

    const struct click_wifi *wifi = (struct click_wifi *)mac_ptr;

    // is this a Beacon frame?
    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    if ((type != WIFI_FC0_TYPE_MGT) || (subtype != WIFI_FC0_SUBTYPE_BEACON)) {
        // not a beacon frame - ignore it
        return p;
    }

    // in Beacon frames, addr2 = "SA" and addr3 = "BSSID"
    EtherAddress sa = EtherAddress(wifi->i_addr2);
    EtherAddress bssid = EtherAddress(wifi->i_addr3);

    int bcnint;
    if (!wifi_parse_bcnint(mac_ptr, frame_len, &bcnint)) {
        // packet truncated or malformed
        return p;
    }

    if (bcnint < 0) {
        _log->warning("invalid beacon (bcn-int = %d) from AP %s",
            bcnint, sa.unparse_colon().c_str());
        return p;
    }

    if (bcnint != 100) {
        _log->debug("beacon interval of %d received from AP %s",
            bcnint, sa.unparse_colon().c_str());
    }

    // note: do not check that SA == BSSID because this element accepts IBSS
    // stations (where this is not the case)

    SnifferMap *smap = _ap_map.findp(sa);
    if (smap == NULL) {
        _ap_map.insert(sa, SnifferMap());
        smap = _ap_map.findp(sa);
        assert(smap != NULL);
    }

    uint32_t wifimerge_offset = WIFIMERGE_ANNO(p);
    if (wifimerge_offset == WIFIMERGE_NOT_PRESENT) {
        _log->warning("packet received with no WifiMerge header");
        return p;
    }

    const u_char *ptr = p->mac_header() - wifimerge_offset;
    assert(ptr >= p->buffer());
    struct argos_wifimerge *wf = (struct argos_wifimerge*)ptr;
    struct argos_wifimerge_elt *elts = (struct argos_wifimerge_elt*)
        (ptr + sizeof(struct argos_wifimerge));

    if (wf->magic != ARGOS_WIFIMERGE_MAGIC) {
        _log->error("missing or bad Argos wifimerge header in received packet");
        return p;
    }

    smap->beacon_capture(bcnint, wf->num_elts, elts);
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FocusChannel)
