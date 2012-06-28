/*
 * staticchannel.{cc,hh} -- implements a fixed-duration channel rotation policy
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "staticchannel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
CLICK_DECLS


StaticChannel::StaticChannel()
    : _log(NULL), _active(true), _timer(this), _interval(1, 0)  // 1 second
{
}

StaticChannel::~StaticChannel()
{
    if (_log != NULL) delete _log;
}

enum { H_ACTIVE, H_CHANPOLL };

void
StaticChannel::add_handlers()
{
    add_data_handlers("active", Handler::OP_READ, &_active);
    add_write_handler("active", write_handler, (void *)H_ACTIVE);
}

int
StaticChannel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "HANDLER", cpkM, cpString, &_setchan_handler_name,
            "CHANNEL", cpkM, cpByte, &_channel,
            "PRIORITY", 0, cpInteger, &_priority,
            "INTERVAL", 0, cpTimestamp, &_interval,
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
StaticChannel::initialize(ErrorHandler *errh)
{
    _timer.initialize(this);
    _timer.schedule_now();

    if (!cp_handler(_setchan_handler_name, Handler::OP_WRITE, &_setchan_element,
            &_setchan_handler, this, errh))
        return -EINVAL;

    return 0;
}

void
StaticChannel::run_timer(Timer *)
{
    _timer.reschedule_after(_interval);
    if (!_active) return;

    // args: <NAME> <PRIORITY> <CHANNEL> <DURATION>
    StringAccum sa;
    sa << name().c_str() << " " << _priority << " " << (int)_channel
       << " " << _interval;

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _setchan_handler->call_write(sa.take_string(), _setchan_element, &errh);
    if (rv >= 0) {
        _log->debug("setchan handler (%hhu) success for %s sec", _channel,
            _interval.unparse().c_str());
    } else {
        if (rv == -EPERM)
            _log->debug("setchan handler (%hhu) failed: %s", _channel,
                errh.get_last_error().c_str());
        else
            _log->error("setchan handler (%hhu) failed: %s", _channel,
                errh.get_last_error().c_str());
    }
}

/* Protected Methods */

bool
StaticChannel::get_active()
{
    return _active;
}

String
StaticChannel::read_handler(Element *e, void *thunk)
{
    StaticChannel *elt = dynamic_cast<StaticChannel*>(e);
    int which = reinterpret_cast<int>(thunk);

    switch (which) {
    case H_ACTIVE:
        return String(elt->get_active());
    default:
        return "<invalid handler>";
    }
}

void
StaticChannel::set_active(bool yes)
{
    _active = yes;
}

int
StaticChannel::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    StaticChannel *elt = dynamic_cast<StaticChannel*>(e);
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
EXPORT_ELEMENT(StaticChannel)
