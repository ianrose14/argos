#ifndef CLICK_TCPREASSEMBLER_HH
#define CLICK_TCPREASSEMBLER_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <clicknet/tcp.h>
#include <click/timer.hh>
CLICK_DECLS

class TCPReassembler : public Element {
public:
    TCPReassembler();
    ~TCPReassembler();

    const char *class_name() const	{ return "TCPReassembler"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const	{ return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet *);

private:
    Timestamp _timeout;

    uint32_t _mem_used;
    uint32_t _mem_high_thresh;
    uint32_t _mem_low_thresh;
};

CLICK_ENDDECLS
#endif
