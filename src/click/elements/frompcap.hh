#ifndef CLICK_FROMPCAP_HH
#define CLICK_FROMPCAP_HH
#include <click/element.hh>
#include <click/task.hh>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#undef PCAP_DONT_INCLUDE_PCAP_BPF_H
#include "buffer.h"

// a few items copied from savefile.c in libpcap
#ifndef TCPDUMP_MAGIC
#define TCPDUMP_MAGIC           0xa1b2c3d4
#endif
#ifndef SWAPLONG
#define SWAPLONG(y) \
    ((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#endif
#ifndef SWAPSHORT
#define SWAPSHORT(y) \
    ( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )
#endif

CLICK_DECLS

/*
=title FromPcap

=c

FromPcap(DEVNAME, [, I<keywords> ...])

=a FromDevice.u, ToDevice.u, FromDump, ToDump, KernelFilter, FromDevice(n) */

class FromPcap : public Element {
public:
    FromPcap();
    ~FromPcap();

    const char *class_name() const	{ return "FromPcap"; }
    const char *port_count() const	{ return PORTS_0_1; }
    const char *processing() const	{ return PUSH; }

    void add_handlers();
    int configure(Vector<String> &, ErrorHandler *);
    int configure_phase() const		{ return CONFIGURE_PHASE_PRIVILEGED; }
    int initialize(ErrorHandler *);

    bool run_task(Task *);
    void selected(int fd);

    int get_stats(u_int &kern_recv, u_int &kern_drop);

    // must be public for pcap callback
    void handle_packet(const struct pcap_pkthdr*, const u_char*);

private:
    void quit();
    bool perform_read();
    bool read_packet();
    bool read_packet_from_buf();
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    // for live captures
    String _ifname;
    pcap_t* _pcap;
    bool _promisc;
    int _snaplen;
    String _bpf_filter;
    bool _bpf_immediate;

    // for offline captures
    String _filename;
    FILE *_fp;
    struct buffer *_buf;
    bool _swapped;
    bool _got_file_header;

    // common variables
    Task _task;
    int _fd;
    Vector<Packet*> _pkts;
    int32_t _burst;
    int _dlt;
    unsigned _headroom;
    int _limit;
    int _bufsize;

    // CPU tracing
    bool _trace_cpu;
    Timestamp _total_cpu_time;
    Timestamp _start_cpu_time;

    // emulate what Click would do with CLICK_STATS >= 2
    click_cycles_t _total_cycles;
    click_cycles_t _start_cycles;

    u_int _last_ps_recv;
    u_int _last_ps_drop;
    u_int _recentered_ps_recv;  // to effect "resets" of pcap stats
    u_int _recentered_ps_drop;
    u_int _mem_drop;
    u_int _total_count;
};

CLICK_ENDDECLS
#endif
