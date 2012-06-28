/*
 * systeminfo.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */
#include <click/config.h>
#include "systeminfo.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/master.hh>
#include <click/router.hh>
#include <click/straccum.hh>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
CLICK_DECLS

SystemInfo::SystemInfo()
    : _timer(this)
{
}

SystemInfo::~SystemInfo()
{
}

enum { H_ALLOC_PKTS, H_HOSTNAME, H_CPU1, H_CPU10, H_CPU60, H_CPU_ALL, H_MAXRSS,
       H_UPTIME, H_CHECK_PACKETS, H_PENDING_TASKS, H_PENDING_TIMERS, H_NEXT_TIMER };

void
SystemInfo::add_handlers()
{
    add_read_handler("alloc_packets", read_handler, (void*)H_ALLOC_PKTS);
    add_read_handler("hostname", read_handler, (void*)H_HOSTNAME);
    add_read_handler("cpu_1", read_handler, (void*)H_CPU1);
    add_read_handler("cpu_10", read_handler, (void*)H_CPU10);
    add_read_handler("cpu_60", read_handler, (void*)H_CPU60);
    add_read_handler("cpu_all", read_handler, (void*)H_CPU_ALL);
    add_read_handler("max_rss", read_handler, (void*)H_MAXRSS);
    add_read_handler("uptime", read_handler, (void*)H_UPTIME);
    add_read_handler("check_packets", read_handler, (void*)H_CHECK_PACKETS);
    set_handler("dump_packets", Handler::OP_READ | Handler::READ_PARAM, dump_packets);

    // these rely on functions that I added to master.hh
    add_read_handler("pending_tasks", read_handler, (void*)H_PENDING_TASKS);
    add_read_handler("pending_timers", read_handler, (void*)H_PENDING_TIMERS);
    add_read_handler("next_timer", read_handler, (void*)H_NEXT_TIMER);
}

void *
SystemInfo::cast(const char *n)
{
    if (strcmp(n, "SystemInfo") == 0)
        return (SystemInfo *)this;
    else
        return 0;
}

int
SystemInfo::initialize(ErrorHandler *errh)
{
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == -1)
        return errh->error("gethostname: %s", strerror(errno));
    _hostname = String(buf);

    // get list of queries from list of elements
    HashMap<String, int> unique_queries;  // value is meaningless
    for (int i=0; i < router()->nelements(); i++) {
        Element *elt = router()->element(i);
        int index = elt->name().find_left('/');
        if (index > -1)
            unique_queries.insert(elt->name().substring(0, index), 1);
    }

    _queries.push_back("");
    HashMap<String, int>::const_iterator iter = unique_queries.begin();
    for (; iter != unique_queries.end(); iter++)
        _queries.push_back(iter.key());

    Timestamp now = Timestamp::now();
    struct rusage rusage;
    if (getrusage(RUSAGE_SELF, &rusage) == -1)
        return errh->error("getrusage: %s", strerror(errno));

    _last_rusage_cpu = Timestamp(rusage.ru_utime) + Timestamp(rusage.ru_stime);
    _last_cpu_check = now;
    _started = now;
    _starting_rusage_cpu = _last_rusage_cpu;
    _maxrss_kbytes = rusage.ru_maxrss;
    _start_time = now;

    _timer.initialize(this);
    _timer.schedule_after_sec(1);

    return 0;
}

void
SystemInfo::run_timer(Timer *)
{
    struct rusage rusage;
    if (getrusage(RUSAGE_SELF, &rusage) == -1) {
        click_chatter("getrusage: %s", strerror(errno));
        return;
    }

    _maxrss_kbytes = rusage.ru_maxrss;
    Timestamp now = Timestamp::now();
    Timestamp elapsed = now - _last_cpu_check;
    Timestamp total_cpu = Timestamp(rusage.ru_utime) + Timestamp(rusage.ru_stime);
    Timestamp this_cpu = total_cpu - _last_rusage_cpu;

    double this_cpu_sec = this_cpu.doubleval();
    double elapsed_sec = elapsed.doubleval();
    double pcpu = this_cpu_sec / elapsed_sec;

    // sometimes the timer tick is delayed - if its more than 0.5s delayed we
    // print a warning
    // todo
    if (elapsed > Timestamp::make_msec(1, 500)) {
        click_chatter("%s warning: timer delayed by %s (cpu: %.3fs, wallclock: %.3fs)",
            name().c_str(), (elapsed - Timestamp(1, 0)).unparse().c_str(),
            this_cpu_sec, elapsed_sec);
        /*
        fprintf(stderr, "%s: System timer scheduled for %s\n", now.unparse().c_str(),
            _timer.expiry().unparse().c_str());
        RouterThread::itr_stack_print();
        */
    }

    // also, if the timer tick is early (which should never happen) we print a
    // warning and do NOT calculate cpu usage because the values can be
    // misleading (such as >100% cpu usage) over very small timer intervals
    if (elapsed < Timestamp::make_msec(0, 900)) {
        click_chatter("%s warning: timer ticked early (interval only %s)",
            name().c_str(), elapsed.unparse().c_str());

        // tick again when we were supposed to
        _timer.schedule_at(_last_cpu_check + Timestamp(1, 0));
    }

    _cpu_usage_msec.push_front((uint32_t)round(pcpu*1000));
    if (_cpu_usage_msec.size() > 60) _cpu_usage_msec.pop_back();

    _last_rusage_cpu = total_cpu;
    _last_cpu_check = now;

    // note that we use 'schedule_after' rather than 'reschedule_after' so, if a
    // timer tick is delayed, it isn't followed by a very short timer interval
    _timer.schedule_after_sec(1);
}

String
SystemInfo::get_avg_cpu(int secs) const
{
    uint32_t msec_avg = get_avg_cpu_msec(secs);
    uint32_t sec = msec_avg/1000;
    uint32_t msec = msec_avg - sec*1000;

    char cbuf[32];
    snprintf(cbuf, sizeof(cbuf), "%d.%03d", sec, msec);
    return String(cbuf);
}

uint32_t
SystemInfo::get_avg_cpu_msec(int secs) const
{
    if (secs > _cpu_usage_msec.size())
        secs = _cpu_usage_msec.size();

    if (secs == 0)
        return 0;

    uint32_t msec_sum = 0;
    for (int i=0; i < secs; i++)
        msec_sum += _cpu_usage_msec[i];

    return (msec_sum + (secs/2))/secs;  // (secs/2) is for rounding
}

int
SystemInfo::dump_packets(int, String &s, Element*, const Handler*, ErrorHandler *errh)
{
    int c;
    if (!cp_integer(s, &c))
        return errh->error("expected integer count, not '%s'", s.c_str());
    StringAccum sa;
    const Packet *p = Packet::chain_head();
    for (int i=0; i < c; i++) {
        if (p == NULL) break;
        const Element *e = p->owner();
        sa << i << ": " << (void*)p
           << ", owner=" << (e == NULL ? "NULL" : e->name())
           << ", ts=" << p->timestamp_anno().unparse()
           << ", use_count=" << p->use_count()
           << "\n";
        p = p->chain_next();
    }
    s = sa.take_string();
    return 0;
}

String
SystemInfo::read_handler(Element *e, void *thunk)
{
    const SystemInfo *elt = static_cast<SystemInfo *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_ALLOC_PKTS:
        return String(Packet::packet_allocs()) + "/" +
            String(Packet::payload_allocs());
    case H_HOSTNAME:
        return elt->_hostname;
    case H_CPU1:
        return elt->get_avg_cpu(1);
    case H_CPU10:
        return elt->get_avg_cpu(10);
    case H_CPU60:
        return elt->get_avg_cpu(60);
    case H_CPU_ALL: {
        double ratio = (elt->_last_rusage_cpu - elt->_starting_rusage_cpu).doubleval() /
            (elt->_last_cpu_check - elt->_started).doubleval();
        char cbuf[32];
        snprintf(cbuf, sizeof(cbuf), "%.3f", ratio);
        return String(cbuf);
    }
    case H_MAXRSS:
        return String(elt->_maxrss_kbytes);
    case H_UPTIME:
        return (Timestamp::now() - elt->_start_time).unparse();
    case H_CHECK_PACKETS: {
        const Packet *p = Packet::chain_head();
        const Packet *q = Packet::chain_tail();

        int c = 0;
        const Packet *p2 = p;
        while (p2 != NULL) {
            c++;
            assert(p2 != p2->chain_next());
            p2 = p2->chain_next();
        }

        StringAccum sa;
        sa << "count=" << c << ", ";

        sa << "head=";
        if (p == NULL) {
            sa << "NULL";
        } else {
            sa << "[owner=";
            const Element *e = p->owner();
            sa << (e == NULL ? "NULL" : e->name());
            sa << ";" << p->timestamp_anno().unparse() << "]";
        }

        sa << ", tail=";
        if (q == NULL) {
            sa << "NULL";
        } else {
            sa << "[owner=";
            const Element *e = q->owner();
            sa << (e == NULL ? "NULL" : e->name());
            sa << ";" << q->timestamp_anno().unparse() << "]";
        }

        return sa.take_string();
    }
    case H_PENDING_TASKS:
        return String(elt->master()->pending_tasks());
    case H_PENDING_TIMERS:
        return String(elt->master()->pending_timers());
    case H_NEXT_TIMER:
        return elt->master()->next_timer_expiry().unparse();
    default:
        return String("internal error (bad thunk value)");    
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SystemInfo)
