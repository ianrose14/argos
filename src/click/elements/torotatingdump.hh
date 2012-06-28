#ifndef CLICK_TOROTATINGDUMP_HH
#define CLICK_TOROTATINGDUMP_HH
#include <click/element.hh>
#include <click/error.hh>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#undef PCAP_DONT_INCLUDE_PCAP_BPF_H
CLICK_DECLS

/*
=c

ToRotatingDump()

*/

class ToRotatingDump : public Element {
public:
    ToRotatingDump();
    ~ToRotatingDump();

    const char *class_name() const	{ return "ToRotatingDump"; }
    const char *port_count() const	{ return "1/0-1"; }

    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet *);

private:
    int open_dumper(struct tm*, ErrorHandler*);

    int _dlt;
    String _filename;
    String _dir;
    int _max_files;

    pcap_t *_pcap;
    pcap_dumper_t *_dumper;
    struct tm _opened;
    bool _auto_flush;
};

CLICK_ENDDECLS
#endif
