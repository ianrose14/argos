/*
 * basicchannelmanager.{cc,hh} -- arbitrates access to sniffers' channels,
 *    ignoring queries' priorities
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "basicchannelmanager.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <unistd.h>
#include "../argos/anno.h"
CLICK_DECLS


BasicChannelManager::BasicChannelManager()
    : _active(true), _max_history(64), _current_channel(0),
      _current_lease_priority(255), _log(NULL)
{
}

BasicChannelManager::~BasicChannelManager()
{
    if (_log != NULL) delete _log;
}

enum {
    H_STATS,
    H_RESET,
    H_CANCEL_LEASE,
    H_LEASE_CHANNEL,
};

void
BasicChannelManager::add_handlers()
{
    add_read_handler("stats", read_handler, (void*)H_STATS);
    add_write_handler("reset", write_handler, (void*)H_RESET);
    add_write_handler("cancel_lease", write_handler, (void*)H_CANCEL_LEASE);
    add_write_handler("lease_channel", write_handler, (void*)H_LEASE_CHANNEL);
}

int
BasicChannelManager::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "GET_HANDLER", cpkP+cpkM, cpString, &_getchan_handler_name,
            "SET_HANDLER", cpkP+cpkM, cpString, &_setchan_handler_name,
            "ACTIVE", 0, cpBool, &_active,
            "MAX_HISTORY", 0, cpInteger, _max_history,
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
BasicChannelManager::initialize(ErrorHandler *errh)
{
    if (!cp_handler(_getchan_handler_name, Handler::OP_READ, &_getchan_element,
            &_getchan_handler, this,errh))
        return -EINVAL;

    if (!cp_handler(_setchan_handler_name, Handler::OP_WRITE, &_setchan_element,
            &_setchan_handler, this, errh))
        return -EINVAL;

    reset_stats();

    // look up the current channel
    int channel = get_channel();
    if (channel == -1)
        return errh->error("failed to look up current channel");

    Timestamp now = Timestamp::now();

    _current_channel = channel;
    _last_durations_update = now;

    ChannelChange cc = ChannelChange();
    cc.start_ts = now;
    cc.end_ts = now;
    cc.channel = channel;
    _history.push_back(cc);
    return 0;
}

Packet*
BasicChannelManager::simple_action(Packet *p)
{
    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;

    if (sniff->magic != ARGOS_SNIFF_MAGIC) {
        _log->error("packet received with no Argos-Sniff annotation");
        return p;  // no Argos-sniffer anno - just ignore this packet
    }

    // figure out what channel we were tuned to when this packet was captured
    sniff->channel = 0;
    for (int i=_history.size()-1; i >= 0; i--) {
        if (p->timestamp_anno() > _history[i].start_ts) {
            sniff->channel = _history[i].channel;
            break;
        }
    }

    if (sniff->channel == 0) {
        if (_history.size() == 0)
            _log->debug("failed to set channel anno.  p->ts=%s  first.start=<NONE>",
                p->timestamp_anno().unparse().c_str());
        else
            _log->debug("failed to set channel anno.  p->ts=%s  first.start=%s",
                p->timestamp_anno().unparse().c_str(), _history.front().start_ts.unparse().c_str());
    }

    return p;
}


/*
 * Private Methods
 */

int
BasicChannelManager::cancel_lease_handler(const String &s_in, ErrorHandler *errh)
{
    int key;

    if (cp_va_kparse(s_in, this, errh,
            "KEY", cpkP+cpkM, cpInteger, &key,
            cpEnd) < 0)
        return -EINVAL;

    if (_current_lease_priority == 255) {
        // no lease to cancel...
        _log->debug("cancel-lease failed: no active lease");
        return -ESRCH;
    }
    else if (key == _current_lease_key) {
        // abort current lease
        _log->debug("current lease (ch %hhu) cancelled", _current_channel);
        _current_lease_priority = 255;  // 255 means no current lease
        return 0;
    }
    else {
        // not allowed to cancel leases that don't belong to you
        _log->debug("cancel-lease failed: not owner");
        return -EPERM;
    }
}

bool
BasicChannelManager::change_channel(uint8_t channel)
{
    if (channel > MAX_80211_CHANNEL) {
        _log->critical("invalid channel argument to change_channel: %d", channel);
        return false;
    }

    if (channel == _current_channel) return true;

    Timestamp started = Timestamp::now();

    _channel_durations[_current_channel-1] += (started - _last_durations_update);

    StoredErrorHandler errh = StoredErrorHandler();
    String args = String((int)channel);
    int rv = _setchan_handler->call_write(args, _getchan_element, &errh);

    if (rv < 0) {
        _log->error("setchan handler failed: %s", errh.get_last_error().c_str());
        return false;
    }

    Timestamp finished = Timestamp::now();

    _log->debug("set channel to %d (handler took %s sec)", channel,
        (finished - started).unparse().c_str());

    ChannelChange cc = ChannelChange();
    cc.start_ts = started;
    cc.end_ts = finished;
    cc.channel = channel;
    _history.push_back(cc);

    if (_history.size() > _max_history)
        _history.pop_front();

    _current_channel = channel;
    _last_durations_update = finished;

    return true;
}

int
BasicChannelManager::get_channel()
{
    String rv = _getchan_handler->call_read(_getchan_element);
    int c;
    if (cp_integer(rv, &c))
        return c;
    else
        return -1;
}

int
BasicChannelManager::lease_channel_handler(const String &s_in, ErrorHandler *errh)
{
    String name;
    int priority;
    Timestamp duration;
    uint8_t channel;

    Vector<String> conf;
    cp_spacevec(s_in, conf);

    if (cp_va_kparse(conf, this, errh,
            "NAME", cpkP+cpkM, cpString, &name,
            "PRIORITY", cpkP+cpkM, cpInteger, &priority,
            "CHANNEL", cpkP+cpkM, cpByte, &channel,
            "DURATION", cpkP+cpkM, cpTimestamp, &duration,
            cpEnd) < 0)
        return -EINVAL;

    // the current lease might already have expired
    Timestamp now = Timestamp::now();
    Timestamp remaining = _current_lease_end - now;
    if (remaining <= 0)
        _current_lease_priority = 255;  // 255 means "no current lease"

    if (_current_lease_priority != 255) {
        if (name == _current_lease_owner) {
            // always ok to interrupt your own leases
            _log->debug("lease interrupted by owner (%s) with %s sec left",
                name.c_str(), remaining.unparse().c_str());
        }
        else if (priority > _current_lease_priority) {
            // rejected
            _log->debug("lease-channel w/ priority %d failed: permission denied"
                " (current lease priority: %d)", priority, _current_lease_priority);
            errh->error(strerror(EPERM));
            return -EPERM;
        } else {
            // abort current lease
            _log->debug("lease by %s (priority %d) aborted by %s (priority %d) with %s sec left",
                _current_lease_owner.c_str(), _current_lease_priority,
                name.c_str(), priority, remaining.unparse().c_str());
        }
    }

    // ok to assign a new lease at this point
    if (!change_channel(channel))
        return errh->error("failed to change channel");

    _log->debug("assigned lease (ch %hhu) to %s (priority %d) for %s sec",
        channel, name.c_str(), priority, duration.unparse().c_str());

    _current_lease_owner = name;
    _current_lease_priority = priority;
    _current_lease_end = now + duration;
    _current_lease_key++;
    return _current_lease_key;
}

void
BasicChannelManager::reset_stats()
{
    for (int i=0; i < MAX_80211_CHANNEL; i++)
        _channel_durations[i].assign(0,0);

    _last_durations_update = Timestamp::now();
}

String
BasicChannelManager::read_handler(Element *e, void *thunk)
{
    const BasicChannelManager *elt = static_cast<BasicChannelManager *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_STATS: {
        Timestamp now = Timestamp::now();
        StringAccum sa;
        for (int i=0; i < MAX_80211_CHANNEL; i++) {
            Timestamp val = elt->_channel_durations[i];
            if (i == (elt->_current_channel - 1))
                val += (now - elt->_last_durations_update);
            sa << "c" << (i+1) << "=" << val.unparse() << " ";
        }
        return sa.take_string();
    }
    default:
        return "internal error (bad thunk value)";
    }
}

int
BasicChannelManager::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    BasicChannelManager *elt = static_cast<BasicChannelManager *>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET:
        elt->reset_stats();
        return 0;
    case H_CANCEL_LEASE:
        if (!elt->_active) return 0;
        return elt->cancel_lease_handler(s_in, errh);
    case H_LEASE_CHANNEL:
        if (!elt->_active) return 0;
        return elt->lease_channel_handler(s_in, errh);
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(BasicChannelManager)
