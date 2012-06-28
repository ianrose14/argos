/*
 * packettypeswitch.{cc,hh} -- pretty-print Argos stats messages
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "packettypeswitch.hh"
#include <click/error.hh>
#include <click/confparse.hh>
CLICK_DECLS


PacketTypeSwitch::PacketTypeSwitch()
{
}

PacketTypeSwitch::~PacketTypeSwitch()
{
}

void
PacketTypeSwitch::push(int, Packet *p)
{
    checked_output_push(p->packet_type_anno(), p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PacketTypeSwitch)
ELEMENT_MT_SAFE(PacketTypeSwitch)
