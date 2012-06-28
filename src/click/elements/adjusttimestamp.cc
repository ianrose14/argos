/*
 * adjusttimestamp.{cc,hh} -- modify packets' timestamp annotations.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "adjusttimestamp.hh"
#include <click/confparse.hh>
CLICK_DECLS


AdjustTimestamp::AdjustTimestamp()
    : _delta(0, 0)
{
}

AdjustTimestamp::~AdjustTimestamp()
{
}

int
AdjustTimestamp::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "DELTA", 0, cpTimestamp, &_delta,
            cpEnd) < 0)
        return -1;
    return 0;
}

Packet *
AdjustTimestamp::simple_action(Packet *p)
{
    if (! _delta)  // if timestamp is 0-valued...
        _delta = Timestamp::now() - p->timestamp_anno();

    p->timestamp_anno() += _delta;

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(AdjustTimestamp)
