#ifndef CLICK_SYSTEMINFO_HH
#define CLICK_SYSTEMINFO_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/timestamp.hh>
#include <click/vector.hh>
#include <click/dequeue.hh>
CLICK_DECLS

/*
=c

SystemInfo()

*/

class SystemInfo : public Element {
public:
    SystemInfo();
    ~SystemInfo();

    const char *class_name() const	{ return "SystemInfo"; }
    const char *port_count() const	{ return PORTS_0_0; }

    void add_handlers();
    void * cast(const char *);
    int initialize(ErrorHandler*);
    void run_timer(Timer*);

    String get_avg_cpu(int secs) const;
    uint32_t get_avg_cpu_msec(int secs) const;

private:
    static int dump_packets(int, String&, Element*, const Handler*, ErrorHandler*);
    static String read_handler(Element*, void*);

    Timer _timer;
    String _hostname;
    DEQueue<uint32_t> _cpu_usage_msec;
    Vector<String> _queries;
    Timestamp _last_rusage_cpu;
    Timestamp _last_cpu_check;
    long _maxrss_kbytes;
    Timestamp _start_time;

    // for cpu_all handler
    Timestamp _started;
    Timestamp _starting_rusage_cpu;
};

CLICK_ENDDECLS
#endif
