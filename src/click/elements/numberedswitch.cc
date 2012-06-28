/*
 * numberedswitch.{cc,hh} -- element routes packets to one output of several
 * Ian Rose.  Based on Switch element by Eddie Kohler
 */

#include <click/config.h>
#include "numberedswitch.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
CLICK_DECLS

NumberedSwitch::NumberedSwitch()
{
}

NumberedSwitch::~NumberedSwitch()
{
}

void
NumberedSwitch::push(int, Packet *p)
{
    int output_port = PACKET_NUMBER_ANNO(p);
    checked_output_push(output_port, p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(NumberedSwitch)
ELEMENT_MT_SAFE(NumberedSwitch)
