/*
 * fixedchanrotate.{cc,hh} -- implements a fixed-duration channel rotation policy
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "fixedchanrotate.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include "wifichannel.hh"
CLICK_DECLS


FixedChanRotate::FixedChanRotate()
    : _active(true), _delayed(false), _timer(this), _interval(1),
      _sync_timer(this), _synchronized(false), _hop_index(0), _priority(10)
{
    // default hop sequence = iterate through all channels in order
    for (uint8_t i=1; i <= MAX_80211_CHANNEL; i++) {
        _hop_sequence.push_back(i);
    }
}

FixedChanRotate::~FixedChanRotate()
{
}

enum { H_ACTIVE };

void
FixedChanRotate::add_handlers()
{
    add_data_handlers("active", Handler::OP_READ, &_active);
    add_write_handler("active", write_handler, (void *)H_ACTIVE);
}

int
FixedChanRotate::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool has_pattern = false;
    String pattern, loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "HANDLER", cpkM, cpString, &_setchan_handler_name,
            "PRIORITY", 0, cpInteger, &_priority,
            "INTERVAL", 0, cpTimestamp, &_interval,
            "SYNCHRONIZE", cpkC, &_synchronized, cpTimestamp, &_sync_interval,
            "PATTERN", cpkC, &has_pattern, cpString, &pattern,
            "DELAY", cpkC, &_delayed, cpTimestamp, &_delay,
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

    if (has_pattern) {
        _hop_sequence.clear();

        Vector<String> parts;
        cp_spacevec(pattern, parts);
        if (parts.size() == 0)
            return errh->error("no PATTERN specified");

        int val;
        for (int i=0; i < parts.size(); i++) {
            if (!cp_integer(parts[i], &val))
                return errh->error("error parsing PATTERN value"
                    " (non-integer encountered)");

            _hop_sequence.push_back(val);
        }

        _log->info("configured with interval=%s and hop_sequence=%s",
            _interval.unparse().c_str(), pattern.c_str());
    } else {
        _log->info("configured with interval=%s and default hop_sequence",
            _interval.unparse().c_str());
    }

    if (_synchronized) {
        if (_sync_interval.subsec() != 0)
            return errh->error("bad INTERVAL; partial seconds not supported: %s",
                _sync_interval.unparse().c_str());

        if (((uint32_t)_sync_interval.sec() % 60) != 0)
            return errh->error("bad INTERVAL: must be an even multiple of 1 minute: %s",
                _sync_interval.unparse().c_str());

        uint32_t minutes = _sync_interval.sec()/60;

        if ((60 % minutes) != 0)
            return errh->error("bad INTERVAL: minutes must evenly divide 1 hour: %s",
                _sync_interval.unparse().c_str());
    }

    return 0;
}

int
FixedChanRotate::initialize(ErrorHandler *errh)
{
    _timer.initialize(this);

    if (!cp_handler(_setchan_handler_name, Handler::OP_WRITE, &_setchan_element,
            &_setchan_handler, this, errh))
        return -EINVAL;

    if (_delayed) {
        _active = false;
        _timer.schedule_after(_delay);
    } else {
        _timer.schedule_after(_interval);
    }

    if (_synchronized) {
        _sync_timer.initialize(this);

        struct tm now_tm;
        time_t t = time(NULL);
        localtime_r(&t, &now_tm);

        now_tm.tm_sec = 0;
        now_tm.tm_min = 0;

        Timestamp next_sync = Timestamp::make_sec(mktime(&now_tm));

        while (next_sync < Timestamp::now())
            next_sync = next_sync + _sync_interval;

        _log->info("first sync time: %s", next_sync.unparse().c_str());
        _sync_timer.schedule_at(next_sync);
    }

    return 0;
}

void
FixedChanRotate::run_timer(Timer *timer)
{
    if (timer == &_sync_timer) {
        _hop_index = 0;
        _timer.schedule_at(_sync_timer.expiry() + _interval);
        _sync_timer.reschedule_after(_sync_interval);

        _log->info("synchronized to channel %d at %s; next sync at %s",
            _hop_sequence[0], Timestamp::now().unparse().c_str(),
            _sync_timer.expiry().unparse().c_str());
    }
    else if (timer == &_timer) {
        if (_delayed) {
            _delayed = false;
            _active = true;
            _timer.schedule_after(_interval);
        }

        _hop_index++;
        if (_hop_index >= _hop_sequence.size()) _hop_index = 0;

        // Note that by using reschedule_after() instead of schedule_after(), if
        // some channel interval takes too long, we will screw the next interval
        // (by cutting it short).  However this is the right thing to do because
        // it keeps us on schedule which can be important if we are trying to
        // stay in sync with other nodes
        _timer.reschedule_after(_interval);
        if (!_active) {
            _log->debug("skipping timer tick (active=false)");
            return;
        }

        uint8_t channel = _hop_sequence[_hop_index];

        // args: <NAME> <PRIORITY> <CHANNEL> <DURATION>
        StringAccum sa;
        sa << name().c_str() << " " << _priority << " " << (int)channel
           << " " << _interval;

        StoredErrorHandler errh = StoredErrorHandler();
        int rv = _setchan_handler->call_write(sa.take_string(), _setchan_element, &errh);
        if (rv >= 0) {
            _log->debug("setchan handler (%hhu) success for %s sec", channel,
                _interval.unparse().c_str());
        } else {
            String err = errh.has_error() ? errh.get_last_error() : "??";
            if (rv == -EPERM)
                _log->debug("setchan handler (%hhu) failed: (EPERM) %s", channel,
                    err.c_str());
            else
                _log->error("setchan handler (%hhu) failed: (%d) %s", channel, -rv,
                    err.c_str());
        }
    }
    else
        assert(0  /* invalid timer arg */);
}

/* Protected Methods */

bool
FixedChanRotate::get_active()
{
    return _active;
}

String
FixedChanRotate::read_handler(Element *e, void *thunk)
{
    FixedChanRotate *elt = dynamic_cast<FixedChanRotate*>(e);
    int which = reinterpret_cast<int>(thunk);

    switch (which) {
    case H_ACTIVE:
        return String(elt->get_active());
    default:
        return "<invalid handler>";
    }
}

void
FixedChanRotate::set_active(bool yes)
{
    _active = yes;
}

int
FixedChanRotate::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    FixedChanRotate *elt = dynamic_cast<FixedChanRotate*>(e);
    int which = reinterpret_cast<int>(thunk);
    String s = cp_uncomment(s_in);

    switch (which) {
    case H_ACTIVE: {
        bool active;
        if (cp_bool(s, &active)) {
            elt->set_active(active);
            return 0;
        } else {
            return errh->error("'active' should be Boolean");
        }
    }
    default:
        return errh->error("unknown handler");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FixedChanRotate)
