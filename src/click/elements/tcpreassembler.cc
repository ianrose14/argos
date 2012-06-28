/*
 * tcpreassembler.{cc,hh} -- reassembles TCP streams
 * Ian Rose
 */

#include <click/config.h>
#include "tcpreassembler.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/bitvector.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
CLICK_DECLS

TCPReassembler::TCPReassembler()
    : _timeout(3600,0), _mem_high_thresh(1048576)
{
}

TCPReassembler::~TCPReassembler()
{
}

int
TCPReassembler::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "HIMEM", 0, cpUnsigned, &_mem_high_thresh,
            "TIMEOUT", 0, cpTimestamp, &_timeout,
            cpEnd) < 0)
        return -1;
    return 0;
}

Packet *
TCPReassembler::simple_action(Packet *p)
{
    p->kill();
    return NULL;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TCPReassembler)
