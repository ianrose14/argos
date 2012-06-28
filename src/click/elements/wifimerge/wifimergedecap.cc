/*
 * wifimergedecap.{cc,hh} -- strip Wifi-Merge header from packets.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifimergedecap.hh"
#include "wifimerge.hh"  // for wifi-merge struct definitions
CLICK_DECLS


WifiMergeDecap::WifiMergeDecap()
{
}

WifiMergeDecap::~WifiMergeDecap()
{
}

Packet *
WifiMergeDecap::simple_action(Packet *p)
{
    if (p->length() < sizeof(struct argos_wifimerge)) {
        // bad packet
        checked_output_push(1, p);
        return NULL;
    }

    struct argos_wifimerge *wf = (struct argos_wifimerge*)p->data();

    if (wf->magic != ARGOS_WIFIMERGE_MAGIC) {
        // bad packet
        output(1).push(p);
        return NULL;
    }

    size_t reqlen = sizeof(struct argos_wifimerge) +
        wf->num_elts*sizeof(struct argos_wifimerge_elt);

    if (p->length() < reqlen) {
        // bad packet
        checked_output_push(1, p);
        return NULL;
    }

    // good packet
    p->pull(reqlen);
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiMergeDecap)
