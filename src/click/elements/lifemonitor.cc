/*
 * lifemonitor.{cc,hh} -- sends and receives ping-like messages
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "lifemonitor.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <unistd.h>
CLICK_DECLS

LifeMonitor::LifeMonitor()
    : _timer(this), _send_interval(1), _next_seqnum(0), _verbose(false),
      _error_chatter(false)
{
}

LifeMonitor::~LifeMonitor()
{
}

void
LifeMonitor::add_handlers()
{
    set_handler("count", Handler::OP_READ | Handler::READ_PARAM, counts_handler);
    set_handler("drops", Handler::OP_READ | Handler::READ_PARAM, drops_handler);
    set_handler("last_ping", Handler::OP_READ | Handler::READ_PARAM, last_ping_handler);
    set_handler("latency_ms", Handler::OP_READ | Handler::READ_PARAM, latency_handler);
    add_write_handler("reset_counts", reset_handler, NULL);
}

int
LifeMonitor::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool has_interval = false;

    if (cp_va_kparse(conf, this, errh,
            "INTERVAL", cpkC, &has_interval, cpTimestamp, &_send_interval,
            "ERRORS", 0, cpBool, &_error_chatter,
            "VERBOSE", 0, cpBool, &_verbose,
            cpEnd) < 0)
        return -1;

    if (has_interval) {
        if ((_send_interval != Timestamp(0)) && (noutputs() == 0))
            return errh->error("non-zero INTERVAL specified, but element has no output port");
    }

    return 0;
}

int
LifeMonitor::initialize(ErrorHandler *)
{
    // this element can be instantiated in "receive only" mode, meaning it has
    // no output ports - in this case, simply don't start the timer
    if (noutputs() && (_send_interval != Timestamp(0))) {
        _timer.initialize(this);
        _timer.schedule_now();
        _clock = Timestamp::now();
    }

    return 0;
}

void
LifeMonitor::push(int, Packet *p)
{
    Timestamp now = Timestamp::now();
    
    if (p->length() != sizeof(struct lifemonitor_msg)) {
        if (_error_chatter)
            click_chatter("%s: invalid packet received (length=%d)",
                name().c_str(), p->length());
        p->kill();
        return;
    }

    struct lifemonitor_msg *msg = (struct lifemonitor_msg*)p->data();

    // verify magic number to catch errors (e.g. elements wired wrong)
    if (ntohl(msg->magic_num) != LIFEMONITOR_MAGIC) {
        if (_error_chatter)
            click_chatter("%s: invalid packet received (bad magic number)",
                name().c_str());
        p->kill();
        return;
    }

    // packet seems ok
    Timestamp delay = now - p->timestamp_anno();
    IPAddress src = MISC_IP_ANNO(p);
    uint32_t seqnum = ntohl(msg->seqnum);

    ClientInfo *infop = _clients.findp(src);
    if (infop == NULL) {
        ClientInfo info = ClientInfo();
        info.avg_delay_ms = DirectEWMA();
        info.avg_delay_ms.update(delay.msecval());
        info.last_recv = p->timestamp_anno();
        info.counts = 1;
        info.drops = seqnum;
        info.last_seqnum = seqnum;
        _clients.insert(src, info);

        if (_verbose)
            click_chatter("ping from %s with delay %s and seqnum %u (first)",
                src.unparse().c_str(), delay.unparse().c_str(), seqnum);
    } else {
        if (seqnum == 0) {
            // assume client is restarting from 0
            infop->avg_delay_ms.update(delay.msecval());
            infop->last_recv = p->timestamp_anno();
            infop->counts++;
            infop->last_seqnum = seqnum;

            if (_verbose)
                click_chatter("ping from %s with delay %s and seqnum %u (restarted)",
                    src.unparse().c_str(), delay.unparse().c_str(), seqnum);
        }
        else if (seqnum > infop->last_seqnum) {
            uint32_t gap = seqnum - infop->last_seqnum - 1;
            infop->avg_delay_ms.update(delay.msecval());
            infop->last_recv = p->timestamp_anno();
            infop->counts++;
            infop->drops += gap;
            infop->last_seqnum = seqnum;

            if (_verbose)
                click_chatter("ping from %s with delay %s and seqnum %u (gap: %u)",
                    src.unparse().c_str(), delay.unparse().c_str(), seqnum, gap);
        }
        else {
            if (_error_chatter)
                click_chatter("warning: duplicate or out-of-order ping from %s"
                    " (seqnum %u recv'd after %u)",
                    src.unparse().c_str(), seqnum, infop->last_seqnum);
        }
    }

    p->kill();
}

void
LifeMonitor::run_timer(Timer*)
{
    uint32_t seqnum = _next_seqnum++;
    struct lifemonitor_msg msg;
    msg.magic_num = htonl(LIFEMONITOR_MAGIC);
    msg.seqnum = htonl(seqnum);

    Packet *p = Packet::make(0, &msg, sizeof(msg), 0);
    p->set_timestamp_anno(_clock);

    if (_verbose)
        click_chatter("sending ping with seqnum %u and ts %s", seqnum,
            p->timestamp_anno().unparse().c_str());

    _clock += _send_interval;
    _timer.schedule_at(_clock);
    output(0).push(p);
}

/*
 * Private Methods
 */

int
LifeMonitor::counts_handler(int, String &s, Element *e, const Handler*, ErrorHandler *errh)
{
    const LifeMonitor *elt = static_cast<LifeMonitor*>(e);
    IPAddress a;
    if (cp_ip_address(s, &a, elt)) {
        Timestamp last;
        const ClientInfo *infop = elt->_clients.findp(a);
        if (infop == NULL) {
            s = "0";
            return 0;
        }
        s = String(infop->counts);
        return 0;
    } else
        return errh->error("expected IP address, not '%s'", s.c_str());
}

int
LifeMonitor::drops_handler(int, String &s, Element *e, const Handler*, ErrorHandler *errh)
{
    const LifeMonitor *elt = static_cast<LifeMonitor*>(e);
    IPAddress a;
    if (cp_ip_address(s, &a, elt)) {
        Timestamp last;
        const ClientInfo *infop = elt->_clients.findp(a);
        if (infop == NULL) {
            s = "0";
            return 0;
        }
        s = String(infop->drops);
        return 0;
    } else
        return errh->error("expected IP address, not '%s'", s.c_str());
}

int
LifeMonitor::last_ping_handler(int, String &s, Element *e, const Handler*, ErrorHandler *errh)
{
    const LifeMonitor *elt = static_cast<LifeMonitor*>(e);
    IPAddress a;
    if (cp_ip_address(s, &a, elt)) {
        Timestamp last;
        const ClientInfo *infop = elt->_clients.findp(a);
        if (infop == NULL) {
            s = "0";
            return 0;
        }
        s = infop->last_recv.unparse().c_str();
        return 0;
    } else
        return errh->error("expected IP address, not '%s'", s.c_str());
}

int
LifeMonitor::latency_handler(int, String &s, Element *e, const Handler*, ErrorHandler *errh)
{
    const LifeMonitor *elt = static_cast<LifeMonitor*>(e);
    IPAddress a;
    if (cp_ip_address(s, &a, elt)) {
        Timestamp last;
        const ClientInfo *infop = elt->_clients.findp(a);
        if (infop == NULL) {
            s = "0";
            return 0;
        }
        s = String(infop->avg_delay_ms.unscaled_average());
        return 0;
    } else
        return errh->error("expected IP address, not '%s'", s.c_str());
}

int
LifeMonitor::reset_handler(const String &s, Element *e, void *,
    ErrorHandler *errh)
{
    LifeMonitor *elt = static_cast<LifeMonitor*>(e);
    IPAddress a;
    if (cp_ip_address(s, &a, elt)) {
        Timestamp last;
        ClientInfo *infop = elt->_clients.findp(a);
        if (infop == NULL)
            return errh->error("unknown IP: %s", s.c_str());
        infop->drops = 0;
        infop->counts = 0;
        return 0;
    } else
        return errh->error("expected IP address, not '%s'", s.c_str());
}


CLICK_ENDDECLS
EXPORT_ELEMENT(LifeMonitor)
