#ifndef CLICK_WIFICHANNEL_HH
#define CLICK_WIFICHANNEL_HH
#include <click/element.hh>
#include <sys/ioctl.h>
#include <net/if.h>  /* must be included before net80211/ieee80211_ioctl.h */
#include <net80211/ieee80211_ioctl.h>
CLICK_DECLS

#define MAX_80211_CHANNEL 11

/*
=c
WifiChannel()

=s Argos

Arbitrates access to sniffers' channels.

=d
Arbitrates access to sniffers' channels.
*/

class WifiChannel : public Element {
public:
    WifiChannel();
    ~WifiChannel();

    const char *class_name() const      { return "WifiChannel"; }
    const char *port_count() const      { return PORTS_0_0; }

    void add_handlers();
    int configure(Vector<String> &, ErrorHandler*);
    int configure_phase() const		{ return CONFIGURE_PHASE_PRIVILEGED; }
    int initialize(ErrorHandler *);

private:
    int change_channel(uint8_t, ErrorHandler*);
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    String _if_name;  // interface to change channels on
    int _sock;  // for ioctls
    struct ieee80211_channel _channel_info[MAX_80211_CHANNEL+1];
    uint8_t _current_channel, _init_channel;

    // _priv_changes and _hdlr_changes track the same thing, but only
    // _hdlr_changes is reset by the "reset" handler
    uint32_t _priv_changes;
    uint32_t _hdlr_changes, _reloads;

    // on many systems the ioctl to change the channel is a priviledged
    // operation so if needed WifiChannel change seteuid(0) before the ioctl
    // (and set it back afterwards)
    bool _change_euid;

    bool _verbose;
    bool _trace;  // whether to chatter each time the channel is changed
};

CLICK_ENDDECLS
#endif
