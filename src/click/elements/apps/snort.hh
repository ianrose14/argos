#ifndef CLICK_SNORT_HH
#define CLICK_SNORT_HH
#include <click/element.hh>
#include <click/dequeue.hh>
#include <click/etheraddress.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <click/handlercall.hh>
#include <click/hashmap.hh>
#include <click/notifier.hh>
#include <stdio.h>
#include <pcap/pcap.h>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS

/*
=c

Snort()

*/

#define SNORT_PORTSCAN_SIG 7
#define SNORT_PORTSCAN_CLASSIFICATION 0

// IPPair is a better name, but wifi/linktable.hh already defines a class with
// that name
class IPDuo {
public:
    IPDuo(IPAddress s, IPAddress d) : src(s), dst(d) {}
    
    inline size_t hashcode() const { return src.hashcode() ^ dst.hashcode(); }
    String unparse() const {
        char cbuf[128];
        snprintf(cbuf, sizeof(cbuf), "(%s,%s)", src.unparse().c_str(), dst.unparse().c_str());
        return String(cbuf);
    }
    
    friend bool
    operator==(const IPDuo &a, const IPDuo &b);

    IPAddress src, dst;
};

inline bool
operator==(const IPDuo &a, const IPDuo &b)
{
    return (a.src == b.src) && (a.dst == b.dst);
}


class Snort : public Element {
public:
    Snort();
    ~Snort();

    const char *class_name() const	{ return "Snort"; }
    const char *flow_code() const       { return "x/y"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const      { return PULL_TO_PUSH; }

    void add_handlers();
    void cleanup(CleanupStage);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    bool run_task(Task*);
    void run_timer(Timer*);
    void selected(int);

private:
    bool check_snort_proc(int, bool);
    void close_snort_input();
    void db_insert_alert(const Timestamp &, const char*, uint32_t, uint32_t,
        uint32_t, uint32_t);
    void db_insert_portscan(const Timestamp &, const char*, uint32_t, int32_t,
        int32_t, IPAddress, int32_t, IPAddress, IPAddress, int32_t, int32_t,
        int32_t, EtherAddress*, int*);
    int signal_snort_proc(int, ErrorHandler*);
    static int write_handler(const String &, Element *, void *, ErrorHandler *);

    struct SrcInfo {
        EtherAddress ether;
        int capt_node_id;
        Timestamp last_updated;
    };

    // snort process variables
    String _snort_exe;
    Vector<String> _snort_args;
    pid_t _snort_pid;
    int _snort_stdin;  // file descriptor
    FILE *_snort_stdout, *_snort_stderr;

    // variables for receiving packets from upstream and passing them to snort
    int _dlt, _snaplen;
    Packet *_next_packet;
    struct pcap_pkthdr _next_pkthdr;
    size_t _header_written;
    size_t _body_written;

    // variables for receiving packets from snort and passing them downstream
    String _sockfile;
    int _sock;
    HashMap<IPDuo, SrcInfo> _src_info;

    // variables for suppressing duplicate portscan alerts from Snort
    Timestamp _portscan_window;
    HashMap<EtherAddress, Timestamp> _last_portscan_alert;

    Task _task;
    Timer _timer;
    Timestamp _interval;
    NotifierSignal _signal;
    HandlerCall *_end_h;
    PostgreSQL *_db;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
