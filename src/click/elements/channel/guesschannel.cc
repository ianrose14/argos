/*
 * guesschannel.{cc,hh} -- makes a guess at what channel each packet was sent
 * on, and stores that value in the Argos annotation area
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "guesschannel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include "../wifiutil.hh"
#include "../argos/anno.h"
CLICK_DECLS


GuessChannel::GuessChannel()
    : _timer(this), _timeout(300, 0), _gc_interval(10, 0), _log(NULL)
{
}

GuessChannel::~GuessChannel()
{
    if (_log != NULL) delete _log;
}

int
GuessChannel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";
    Element *elt = NULL;

    if (cp_va_kparse(conf, this, errh,
            "TRACKER", cpkM, cpElement, &elt,
            "TIMEOUT", 0, cpSeconds, &_timeout,
            "REAP", 0, cpTimestamp, &_gc_interval,
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

    // check that elt is a pointer to an AssocTracker element
    _assoc_tracker = (AssocTracker*)elt->cast("AssocTracker");
    if (_assoc_tracker == NULL)
        return errh->error("TRACKER element is not an AssocTracker");

    return 0;
}

int
GuessChannel::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_after(_gc_interval);
    return 0;
}

void
GuessChannel::run_timer(Timer *)
{
    Timestamp thresh = Timestamp::now() - _timeout;

    _log->debug("garbage collecting cache...");

    HashMap<EtherAddress, APInfo>::iterator iter = _ap_channel_cache.begin();
    while (iter != _ap_channel_cache.end()) {
        EtherAddress addr;
        bool do_erase = (iter.value().last_updated <= thresh);
        if (do_erase) addr = iter.key();

        // make sure to increment iterator before we remove this entry
        iter++;

        // this entry was last-updated too long ago; expire from cache
        if (do_erase) _ap_channel_cache.remove(addr);
    }
    _timer.reschedule_after(_gc_interval);
}

Packet *
GuessChannel::simple_action(Packet *p)
{
    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;

    if (sniff->magic != ARGOS_SNIFF_MAGIC) {
        _log->error("packet received with no Argos-Sniff annotation");
        return p;
    }

    int recv_chan_est = sniff->channel;

    // update the BSSID->channel cache (if this is a beacon or probe response)
    update_channel_cache(p);

    // based on the frame's addresses, try to guess what channel it was sent on
    int sent_chan_est = estimate_channel(p);

    // if estimate_channel() produced an estimate (i.e. returned a non-zero
    // value), AND the Argos annotation provided a receive channel, then we
    // check if those channels are close enough that the frame could conceivably
    // have been sent on sent_chan_est and yet received on recv_chan_est
    uint8_t overall_chan_est = 0;

    if (sent_chan_est == 0) {
        overall_chan_est = recv_chan_est;
    }
    else if (recv_chan_est == 0) {
        overall_chan_est = sent_chan_est;
    }
    else { // (sent_chan_est != 0) && (recv_chan_est != 0)
        // if the send and receive channels do not match, we trust the send
        // channel estimate - this can occur for many reasons including that
        // nearby 802.11 channels overlap, or that our receive channel might
        // have been recorded incorrectly (e.g. because we were in the midst of
        // changing channels so we couldn't be sure exactly what channel the
        // radio was tuned to when the packet was received, or because the
        // timestamping was slightly off)
        overall_chan_est = sent_chan_est;
    }

    // if there wasn't previously an Argos annotation, then create one
    if (sniff->magic != ARGOS_SNIFF_MAGIC) {
        memset(sniff, '\0', ARGOS_SNIFF_ANNO_SIZE);
        sniff->magic = ARGOS_SNIFF_MAGIC;
    }

    // update channel field of Argos annotation to our new channel estimate
    sniff->channel = overall_chan_est;

    _log->debug("recv_chan_est=%hhu sent_chan_est=%hhu overall_chan_est=%hhu",
        recv_chan_est, sent_chan_est, overall_chan_est);

    return p;
}

/*
 * Private Methods
 */

uint8_t
GuessChannel::estimate_channel(const Packet *p)
{
    EtherAddress bssid;
    if (_assoc_tracker->infer_bssid(p, &bssid)) {
        // no way to infer channel from packets sent to the broadcast BSSID
        // (this typically only occurs in probe requests)
        if (bssid.is_broadcast())
            return 0;

        APInfo *info = _ap_channel_cache.findp(bssid);
        if (info == NULL) {
            _log->debug("no channel mapping for %s", bssid.unparse_colon().c_str());
            return 0;
        }

        return info->channel;
    }

    // else, BSSID could not be inferred from this packet
    return 0;
}

void
GuessChannel::update_channel_cache(const Packet *p)
{
    const struct click_wifi *wifi = (const struct click_wifi *)p->data();

    // all management frames should at least have all of the fields in the click_wifi
    // struct
    if (p->length() < sizeof(struct click_wifi))
        return;

    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    // we only care about Beacon and Probe Response frames
    if (type != WIFI_FC0_TYPE_MGT)
        return;

    if ((subtype != WIFI_FC0_SUBTYPE_BEACON) && (subtype != WIFI_FC0_SUBTYPE_PROBE_RESP))
        return;

    EtherAddress bssid = EtherAddress(wifi->i_addr3);
    if (bssid.is_broadcast())
        return;

    // check for a 'DS Parameter Set' information element (which contains the
    // AP's current channel)
    uint8_t elt_len;
    const u_char *elt;
    if (wifi_parse_infoelt(p->data(), p->length(), WIFI_ELEMID_DSPARMS, &elt_len, &elt)) {
        // sanity check
        if (elt_len != 1) {
            _log->warning("packet received with DS-Params InfoElt of length %d", 
                elt_len);
            return;
        }

        // cache this channel value
        uint8_t channel = elt[0];
        bool isnew = _ap_channel_cache.insert(bssid, APInfo(channel));

        if (isnew)
            _log->debug("inserted new AP channel mapping %s -> %hhu",
                bssid.unparse_colon().c_str(), channel);
        else
            _log->debug("updated existing AP channel mapping %s -> %hhu",
                bssid.unparse_colon().c_str(), channel);
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(GuessChannel)
