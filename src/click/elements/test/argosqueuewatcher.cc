/*
 * argosqueuewatcher.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "argosqueuewatcher.hh"
#include <click/error.hh>
#include <click/confparse.hh>
CLICK_DECLS

ArgosQueueWatcher::ArgosQueueWatcher()
    : _timer(this), _interval(1 /* todo */), _sysinfo(NULL), _log(NULL)
{
}

ArgosQueueWatcher::~ArgosQueueWatcher()
{
    if (_log != NULL) delete _log;
}

enum { H_PREPARE_RESET };

void
ArgosQueueWatcher::add_handlers()
{
    add_write_handler("prepare_counter_reset", write_handler, (void*)H_PREPARE_RESET);
}

int
ArgosQueueWatcher::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String queuestr;
    Element *elt;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "QUEUES", cpkM+cpkP, cpString, &queuestr,
            "SYSINFO", cpkM, cpElement, &elt,
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

    cp_spacevec(queuestr, _queue_names);

    // the number of queues specified should match the number of input ports
    if (_queue_names.size() != ninputs())
        return errh->error("number of queues (%d) does not match input ports (%d)",
            _queue_names.size(), ninputs());

    for (int i=0; i < _queue_names.size(); i++) {
        // we parse these as elements just to ensure that the elements really
        // exist, although we don't use the Element pointers at all
        Element *elt = cp_element(_queue_names[i], this, errh);
        if (elt == NULL)
            return -EINVAL;
    }

    // check that elt is a pointer to a SystemInfo element
    _sysinfo = (SystemInfo*)elt->cast("SystemInfo");
    if (_sysinfo == NULL)
        return errh->error("SYSINFO element is not an SystemInfo");

    return 0;
}

// todo
// things to track(on a timer):
// - input rate of queue  ;  in_all
// - output rate of each queue  ; out_all
// - output rate of all queues (summed)  out_all
// - input rate ; /all
// - cpu rate


// possible reasons for drops:
// - cpu starvation
//   - detect via SystemInfo checks
// - nic busy with incoming data
//   - detect via recv bytecounts
// - nic busy with outgoing data (to same source)
//   - detect via send bytecounts + self queue drain-rate
// - nic busy with outgoing data (to different source)
//   - detect via send bytecounts + summed queues drain-rate
// - nic busy with nearby interference (backoffs)
//   - detect via send+recv bytecounts [low]
// - TCP throughput too low (e.g. NIC is ok, but path to destination is bad)
//   - not sure how to detect this, maybe with TCP_INFO getsockopt?

int
ArgosQueueWatcher::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_after(_interval);
    return 0;
}

void
ArgosQueueWatcher::run_timer(Timer *)
{
    uint32_t msec = _sysinfo->get_avg_cpu_msec(1);
    (void) msec;
}

/*
 * Private Methods
 */

int
ArgosQueueWatcher::write_handler(const String &, Element *e, void *thunk,
    ErrorHandler *errh)
{
    ArgosQueueWatcher *elt = static_cast<ArgosQueueWatcher *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_PREPARE_RESET:
        // todo
        (void) elt;
        return 0;
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ArgosQueueWatcher)
