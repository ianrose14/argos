#ifndef CLICK_PKTPARSE_WRAP_HH
#define CLICK_PKTPARSE_WRAP_HH

#include <click/config.h>
#include <click/packet.hh>
#include <pktparse.h>
CLICK_DECLS

int pktparse_click_packet(const Packet*, int, struct packet*);

CLICK_ENDDECLS
#endif
