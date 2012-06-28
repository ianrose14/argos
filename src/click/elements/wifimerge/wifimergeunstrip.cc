/*
 * wifimergeunstrip.{cc,hh} -- strip Wifi-Merge header from packets.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifimergeunstrip.hh"
#include "wifimerge.hh"  // for wifi-merge struct definitions
#include "../argos/anno.h"
CLICK_DECLS


WifiMergeUnstrip::WifiMergeUnstrip()
{
}

WifiMergeUnstrip::~WifiMergeUnstrip()
{
}

void
WifiMergeUnstrip::push(int, Packet *p)
{
    uint32_t wifimerge_offset = WIFIMERGE_ANNO(p);
    if (wifimerge_offset == WIFIMERGE_NOT_PRESENT) {
        checked_output_push(1, p);
        return;
    }

    const u_char *ptr = p->mac_header() - wifimerge_offset;
    if (ptr < p->buffer()) {
        // offset value must be invalid because we fell off the front of the
        // buffer
        checked_output_push(1, p);
        return;
    }

    int off = ptr - p->data();

    if (off >= 0) {
        p->pull(off);
        output(0).push(p);
    }
    else {
        WritablePacket *q = p->push(-off);
        if (q) output(0).push(q);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiMergeUnstrip)
