/*
 * splitfirst.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "splitfirst.hh"
#include <click/error.hh>
#include <click/confparse.hh>
CLICK_DECLS


SplitFirst::SplitFirst()
    : _count(0)
{
}

SplitFirst::~SplitFirst()
{
}

int
SplitFirst::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "LIMIT", cpkP+cpkM, cpUnsigned, &_limit,
            cpEnd) < 0)
        return -1;
    return 0;
}

void
SplitFirst::push(int, Packet *p)
{
    if ((++_count) <= _limit)
        output(1).push(p);
    else
        output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SplitFirst)
ELEMENT_MT_SAFE(SplitFirst)
