/*
 * geofocuschannel.{cc,hh} -- implements channel focusing using
 *   each sniffer's (hard-coded) geographic neighbors
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "geofocuschannel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include "../argos/anno.h"
#include "unistd.h"
CLICK_DECLS

GeoFocusChannel::GeoFocusChannel()
    : _log(NULL), _focus_duration(30, 0), _focus_cooldown(10, 0),
      _current_focus(0), _self_only(false), _priority(0)
{
}

GeoFocusChannel::~GeoFocusChannel()
{
    if (_log != NULL) delete _log;
}

int
GeoFocusChannel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "SETCHAN_HANDLER", cpkM, cpString, &_setchan_handler_name,
            "FOCUS_HANDLER", 0, cpString, &_focus_handler_name,
            "PRIORITY", 0, cpInteger, &_priority,
            "DURATION", 0, cpTimestamp, &_focus_duration,
            "COOLDOWN", 0, cpTimestamp, &_focus_cooldown,
            "SELF_ONLY", 0, cpBool, &_self_only,
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

    if ((!_self_only) && (_focus_handler_name == ""))
        return errh->error("FOCUS_HANDLER is required if SELF_ONLY=false");

    return 0;
}

int
GeoFocusChannel::initialize(ErrorHandler *errh)
{
    if (!cp_handler(_setchan_handler_name, Handler::OP_WRITE, &_setchan_element,
            &_setchan_handler, this, errh))
        return -1;

    if (!_self_only) {
        if (!cp_handler(_focus_handler_name, Handler::OP_WRITE, &_focus_element,
                &_focus_handler, this, errh))
            return -1;

        char buf[256];
        if (gethostname(buf, sizeof(buf)) == -1)
            return errh->error("gethostname: %s", strerror(errno));

        String hostname = String(buf);
        if (get_neighbors(&hostname, &_neighbors) < 0)
            return errh->error("hostname not recognized by get_neighbors: %s", hostname.c_str());
    }

    return 0;
}

Packet *
GeoFocusChannel::simple_action(Packet *p)
{
    // every incoming packet should have an Argos annotation which carries the
    // packet's channel (otherwise we don't know what channel to focus to)
    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;

    if (sniff->magic != ARGOS_SNIFF_MAGIC) {
        _log->warning("packet received without an Argos-Sniff annotation");
        return p;
    }

    if (sniff->channel == _current_focus) {
        // ok we are already focused on this channel, but check if its been a
        // little while since we sent the focus commands and thus we should
        // refresh them
        if (p->timestamp_anno() < _cooldown_end) {
            // nope - still in cooldown period; just ignore this packet
            return p;
        }
        // else, ok to resend commands, so drop through
    }

    // either we aren't focused on this channel or we are but its ok to resend
    // commands - either way, the actions we take are the same
    _log->info("channel-focusing to channel %d", (int)sniff->channel);

    // arguments to BasicChannelManager.lease_channel handler are:
    // <NAME> <PRIORITY> <CHANNEL> <DURATION>
    StringAccum sa;
    sa << name() << " " << _priority << " " << (int)sniff->channel << " " << _focus_duration;
    String setchan_args = sa.take_string();

    _log->debug("lease-channel args: %s", setchan_args.c_str());

    StoredErrorHandler errh = StoredErrorHandler();

    if (!_self_only) {
        // focus each neighbor by using a remote handler-write call
        for (int i=0; i < _neighbors.size(); i++) {
            // arguments to WifiOverlay.proxy_handler_write handler are:
            // <PEER-IP> <HANDLER-NAME> <ARGS> [...]
            StringAccum sa;
            sa << _neighbors[i] << " " << _setchan_handler_name << " " << setchan_args;
            int rv = _focus_handler->call_write(sa.take_string(), _focus_element, &errh);
            if (rv < 0)
                _log->error("channel-focus for neighbor %s failed: %s",
                    _neighbors[i].unparse().c_str(), errh.get_last_error().c_str());
            else
                _log->info("channel-focus successful to neighbor %s for channel %d",
                    _neighbors[i].unparse().c_str(), (int)sniff->channel);
        }
    }

    // also focus ourselves!
    int rv = _setchan_handler->call_write(setchan_args, _setchan_element, &errh);
    if (rv < 0)
        _log->error("channel-focus for (self) failed: %s", errh.get_last_error().c_str());
    else
        _log->info("channel-focus for (self) successful");

    _cooldown_end = Timestamp::now() + _focus_cooldown;
    _current_focus = sniff->channel;

    return p;
}

/*
 * Private, Static Methods
 */

IPAddress
GeoFocusChannel::host2ip(const char *hostname)
{
    String hname = String(*hostname);

    // Citymd indoor
    int l = strlen("citymd");
    if (strncmp(hostname, "citymd", l) == 0)
        return IPAddress(String("192.168.14.") + String(hostname + l));

    // Harvard outdoor:
    l = strlen("citysense0");
    if (strncmp(hostname, "citysense0", l) == 0)
        return IPAddress(String("192.168.144." + String(hostname + l)));

    // BBN:
    l = strlen("citysense2");
    if (strncmp(hostname, "citysense2", l) == 0) {
        int nodenum;
        if (!cp_integer(String(hostname + l), &nodenum))
            return IPAddress();

        return IPAddress(String("192.168.145." + String(nodenum - 56)));
    }

    return IPAddress();
}

int
GeoFocusChannel::get_neighbors(const String *hostname, Vector<IPAddress> *vec)
{
    // for now we will select the (up to) 3 closest nodes
    if (*hostname == "citymd001") {
        vec->push_back(host2ip("citymd004"));
        vec->push_back(host2ip("citymd005"));
        vec->push_back(host2ip("citymd011"));
        return 0;
    }
    else if (*hostname == "citymd004") {
        vec->push_back(host2ip("citymd001"));
        vec->push_back(host2ip("citymd005"));
        vec->push_back(host2ip("citymd011"));
        return 0;
    }
    else if (*hostname == "citymd005") {
        vec->push_back(host2ip("citymd001"));
        vec->push_back(host2ip("citymd004"));
        vec->push_back(host2ip("citymd011"));
        return 0;
    }
    else if (*hostname == "citymd006") {
        vec->push_back(host2ip("citymd007"));
        vec->push_back(host2ip("citymd010"));
        vec->push_back(host2ip("citymd012"));
        return 0;
    }
    else if (*hostname == "citymd007") {
        vec->push_back(host2ip("citymd006"));
        vec->push_back(host2ip("citymd010"));
        vec->push_back(host2ip("citymd012"));
        return 0;
    }
    else if (*hostname == "citymd009") {
        vec->push_back(host2ip("citymd001"));
        vec->push_back(host2ip("citymd004"));
        vec->push_back(host2ip("citymd011"));
        return 0;
    }
    else if (*hostname == "citymd010") {
        vec->push_back(host2ip("citymd006"));
        vec->push_back(host2ip("citymd007"));
        vec->push_back(host2ip("citymd012"));
        return 0;
    }
    else if (*hostname == "citymd011") {
        vec->push_back(host2ip("citymd001"));
        vec->push_back(host2ip("citymd004"));
        vec->push_back(host2ip("citymd005"));
        return 0;
    }
    else if (*hostname == "citymd012") {
        vec->push_back(host2ip("citymd006"));
        vec->push_back(host2ip("citymd007"));
        vec->push_back(host2ip("citymd010"));
        return 0;
    }
    else if (*hostname == "citysense001") {
        vec->push_back(host2ip("citysense006"));
        vec->push_back(host2ip("citysense007"));
        vec->push_back(host2ip("citysense012"));
        return 0;
    }
    else if (*hostname == "citysense002") {
        vec->push_back(host2ip("citysense004"));
        vec->push_back(host2ip("citysense006"));
        vec->push_back(host2ip("citysense007"));
        return 0;
    }
    else if (*hostname == "citysense003") {
        vec->push_back(host2ip("citysense007"));
        vec->push_back(host2ip("citysense011"));
        vec->push_back(host2ip("citysense012"));
        return 0;
    }
    else if (*hostname == "citysense004") {
        vec->push_back(host2ip("citysense002"));
        vec->push_back(host2ip("citysense006"));
        vec->push_back(host2ip("citysense010"));
        return 0;
    }
    else if (*hostname == "citysense005") {
        vec->push_back(host2ip("citysense005"));
        return 0;
    }
    else if (*hostname == "citysense006") {
        vec->push_back(host2ip("citysense002"));
        vec->push_back(host2ip("citysense004"));
        vec->push_back(host2ip("citysense007"));
        return 0;
    }
    else if (*hostname == "citysense007") {
        vec->push_back(host2ip("citysense001"));
        vec->push_back(host2ip("citysense002"));
        vec->push_back(host2ip("citysense006"));
        return 0;
    }
    else if (*hostname == "citysense010") {
        vec->push_back(host2ip("citysense002"));
        vec->push_back(host2ip("citysense004"));
        vec->push_back(host2ip("citysense007"));
        return 0;
    }
    else if (*hostname == "citysense011") {
        vec->push_back(host2ip("citysense002"));
        vec->push_back(host2ip("citysense003"));
        vec->push_back(host2ip("citysense012"));
        return 0;
    }
    else if (*hostname == "citysense012") {
        vec->push_back(host2ip("citysense001"));
        vec->push_back(host2ip("citysense007"));
        vec->push_back(host2ip("citysense011"));
        return 0;
    }
    else if (*hostname == "citysense259") {
        vec->push_back(host2ip("citysense261"));
        vec->push_back(host2ip("citysense262"));
        vec->push_back(host2ip("citysense266"));
        return 0;
    }
    else if (*hostname == "citysense261") {
        vec->push_back(host2ip("citysense259"));
        vec->push_back(host2ip("citysense262"));
        vec->push_back(host2ip("citysense273"));
        return 0;
    }
    else if (*hostname == "citysense262") {
        vec->push_back(host2ip("citysense259"));
        vec->push_back(host2ip("citysense261"));
        vec->push_back(host2ip("citysense274"));
        return 0;
    }
    else if (*hostname == "citysense263") {
        vec->push_back(host2ip("citysense264"));
        vec->push_back(host2ip("citysense270"));
        vec->push_back(host2ip("citysense271"));
        return 0;
    }
    else if (*hostname == "citysense264") {
        vec->push_back(host2ip("citysense263"));
        vec->push_back(host2ip("citysense271"));
        vec->push_back(host2ip("citysense276"));
        return 0;
    }
    else if (*hostname == "citysense266") {
        vec->push_back(host2ip("citysense259"));
        vec->push_back(host2ip("citysense271"));
        vec->push_back(host2ip("citysense276"));
        return 0;
    }
    else if (*hostname == "citysense268") {
        vec->push_back(host2ip("citysense270"));
        vec->push_back(host2ip("citysense271"));
        vec->push_back(host2ip("citysense275"));
        return 0;
    }
    else if (*hostname == "citysense270") {
        vec->push_back(host2ip("citysense263"));
        vec->push_back(host2ip("citysense268"));
        vec->push_back(host2ip("citysense271"));
        return 0;
    }
    else if (*hostname == "citysense271") {
        vec->push_back(host2ip("citysense264"));
        vec->push_back(host2ip("citysense266"));
        vec->push_back(host2ip("citysense275"));
        return 0;
    }
    else if (*hostname == "citysense273") {
        vec->push_back(host2ip("citysense259"));
        vec->push_back(host2ip("citysense261"));
        vec->push_back(host2ip("citysense276"));
        return 0;
    }
    else if (*hostname == "citysense274") {
        vec->push_back(host2ip("citysense259"));
        vec->push_back(host2ip("citysense261"));
        vec->push_back(host2ip("citysense262"));
        return 0;
    }
    else if (*hostname == "citysense275") {
        vec->push_back(host2ip("citysense268"));
        vec->push_back(host2ip("citysense270"));
        vec->push_back(host2ip("citysense271"));
        return 0;
    }
    else if (*hostname == "citysense276") {
        vec->push_back(host2ip("citysense259"));
        vec->push_back(host2ip("citysense264"));
        vec->push_back(host2ip("citysense273"));
        return 0;
    }
    else if (*hostname == "citysense513") {
        vec->push_back(host2ip("citysense514"));
        return 0;
    }
    else if (*hostname == "citysense514") {
        vec->push_back(host2ip("citysense513"));
        return 0;
    }
    else if (*hostname == "citysense769") {
        vec->push_back(host2ip("citysense770"));
        return 0;
    }
    else if (*hostname == "citysense770") {
        vec->push_back(host2ip("citysense769"));
        return 0;
    }
    else {
        errno = EINVAL;
        return -1;
    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(GeoFocusChannel)
