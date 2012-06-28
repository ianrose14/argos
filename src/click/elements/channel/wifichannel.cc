/*
 * wifichannel.{cc,hh} -- arbitrates access to sniffers' channels.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifichannel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <unistd.h>
CLICK_DECLS


WifiChannel::WifiChannel()
    : _current_channel(0), _init_channel(0), _priv_changes(0),
      _hdlr_changes(0), _reloads(0), _change_euid(false), _verbose(false),
      _trace(false)
{
}

WifiChannel::~WifiChannel()
{
    close(_sock);
}

enum { H_CHANGES, H_GET_CHANNEL, H_RELOADS, H_RESET, H_SET_CHANNEL };

void
WifiChannel::add_handlers()
{
    add_read_handler("changes", read_handler, (void*)H_CHANGES);
    add_read_handler("get_channel", read_handler, (void*)H_GET_CHANNEL);
    add_read_handler("reloads", read_handler, (void*)H_RELOADS);
    add_write_handler("reset", write_handler, (void*)H_RESET);
    add_write_handler("set_channel", write_handler, (void*)H_SET_CHANNEL);
}

int
WifiChannel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "DEVNAME", cpkM, cpString, &_if_name,
            "INITIAL_CHAN", 0, cpByte, &_init_channel,
            "CHANGE_EUID", 0, cpBool, &_change_euid,
            "TRACE", 0, cpBool, &_trace,
            "VERBOSE", 0, cpBool, &_verbose,
            cpEnd) < 0)
        return -1;
    return 0;
}

int
WifiChannel::initialize(ErrorHandler *errh)
{
    // look up the ieee80211_channel struct for each channel ahead of time
    _sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (_sock < 0) errh->error("socket: %s", strerror(errno));

    bzero(_channel_info, sizeof(struct ieee80211_channel) * (MAX_80211_CHANNEL+1));

    struct ieee80211req_chaninfo chaninfo;
    struct ieee80211req ireq;
    bzero(&ireq, sizeof(ireq));
    strlcpy(ireq.i_name, _if_name.c_str(), sizeof(ireq.i_name));
    ireq.i_type = IEEE80211_IOC_CHANINFO;
    ireq.i_data = (void*)(&chaninfo);
    ireq.i_len = sizeof(chaninfo);
        
    if (ioctl(_sock, SIOCG80211, &ireq) < 0)
        return errh->error("ioctl(SIOCG80211) failed for IEEE80211_IOC_CHANINFO");

    for (u_int i = 0; i < chaninfo.ic_nchans; i++) {
        const struct ieee80211_channel *c = &chaninfo.ic_chans[i];
        // note that we do not mask ic_flags (an exact match is required) - this
        // means no 'TURBO' channels or any of that wackness
        if (c->ic_flags == IEEE80211_CHAN_G) {
            int chan = c->ic_ieee;
            if (chan <= MAX_80211_CHANNEL)
                memcpy(&_channel_info[chan], c, sizeof(struct ieee80211_channel));
        }
    }

    for (int i=1; i <= MAX_80211_CHANNEL; i++) {
        if (_channel_info[i].ic_ieee == 0)
            return errh->error("no channel info found for channel %d", i);
    }

    // change to the initial channel, if specified
    if (_init_channel != 0) {
        if (change_channel(_init_channel, errh) != 0)
            return -EINVAL;
    }

    return 0;
}

/*
 * Private Methods
 */

int
WifiChannel::change_channel(uint8_t channel, ErrorHandler *errh)
{
    if (channel > MAX_80211_CHANNEL)
        return errh->error("invalid channel (%hhu)", channel);

    if (channel == _current_channel) return 0;

    Timestamp start = Timestamp::now();

    uid_t euid = geteuid();
    if (_change_euid && (euid != 0)) {
        if (seteuid(0) == -1)
            return errh->error("seteuid(0) from uid %d failed: %s", euid,
                strerror(errno));
    }

    struct ieee80211req ireq;
    memset(&ireq, 0, sizeof(ireq));
    strlcpy(ireq.i_name, _if_name.c_str(), sizeof(ireq.i_name));
    ireq.i_type = IEEE80211_IOC_CURCHAN;
    ireq.i_val = 0;
    ireq.i_len = sizeof(struct ieee80211_channel);
    ireq.i_data = &_channel_info[channel];
    int rv = ioctl(_sock, SIOCS80211, &ireq);

    // make sure to release root even if ioctl fails
    if (_change_euid) {
        if (seteuid(euid) == -1)
            return errh->error("seteuid(%d) failed: %s", euid, strerror(errno));
    }

    if (rv < 0)
        return errh->error("ioctl(SIOCS80211) failed: %s", strerror(errno));

    _priv_changes++;
    _hdlr_changes++;

    Timestamp end = Timestamp::now();
    Timestamp elapsed = end - start;

    if (_trace)
        click_chatter("%s: change-channel to %hhu took %s", end.unparse().c_str(),
            channel, elapsed.unparse().c_str());

    // if the ioctl takes more than 30ms, then this may indicate that the
    // interface needs to be reloaded (perhaps this is due to a driver bug?  I'm
    // not sure)
    if (elapsed.msecval() > 30) {
        if (_verbose)
            click_chatter("%s: change-channel ioctl took %s - reloading device after %u calls",
                end.unparse().c_str(), elapsed.unparse().c_str(), _priv_changes);

        // gain root permissions before calling ifconfig
        if (_change_euid && (euid != 0)) {
            if (seteuid(0) == -1)
                return errh->error("seteuid(0) from uid %d failed: %s", euid,
                    strerror(errno));
        }

        StringAccum sa;
        sa << "ifconfig " << _if_name << " down; ifconfig " << _if_name << " up;";
        String cmd = sa.take_string();
        int rv = system(cmd.c_str());

        // make sure to release root even if system() fails
        if (_change_euid) {
            if (seteuid(euid) == -1)
                return errh->error("seteuid(%d) failed: %s", euid, strerror(errno));
        }

        if (rv != 0)
            return errh->error("'%s' failed: %d", cmd.c_str(), rv);

        _reloads++;
        _priv_changes = 0;

        if (_trace) {
            Timestamp now = Timestamp::now();
            Timestamp elapsed = now - end;
            click_chatter("%s: device reload took %s", now.unparse().c_str(),
                elapsed.unparse().c_str());
        }
    }

    _current_channel = channel;
    return 0;
}

String
WifiChannel::read_handler(Element *e, void *thunk)
{
    const WifiChannel *elt = static_cast<WifiChannel *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_CHANGES:
        return String(elt->_hdlr_changes);
    case H_GET_CHANNEL:
        return String((int)elt->_current_channel);
    case H_RELOADS:
        return String(elt->_reloads);
    default:
        return "internal error (bad thunk value)";
    }
}

int
WifiChannel::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    WifiChannel *elt = static_cast<WifiChannel *>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET:
        elt->_hdlr_changes = 0;
        elt->_reloads = 0;
        return 0;
    case H_SET_CHANNEL: {
        u_int channel;
        if (!cp_integer(s_in, &channel))
            return -EINVAL;
        return elt->change_channel((uint8_t)channel, errh);
    }
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiChannel)
