/*
 * striptomac.{cc,hh} -- element strips to MAC header
 * Ian Rose
 */

#include <click/config.h>
#include "striptomac.hh"
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

StripToMACHeader::StripToMACHeader()
{
}

StripToMACHeader::~StripToMACHeader()
{
}

Packet *
StripToMACHeader::simple_action(Packet *p)
{
    int off = p->mac_header_offset();
    if (off >= 0) {
	p->pull(off);
	return p;
    } else
	return p->nonunique_push(-off);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StripToMACHeader)
ELEMENT_MT_SAFE(StripToMACHeader)
