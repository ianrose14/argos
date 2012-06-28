/*
 * bssidfilter.{cc,hh} -- selectively drop 802.11 frames based on BSSID
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "bssidfilter.hh"
#include <click/confparse.hh>
#include "wifiutil.hh"
CLICK_DECLS


BSSIDFilter::BSSIDFilter()
{
}

BSSIDFilter::~BSSIDFilter()
{
}

int
BSSIDFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "BSSID", cpkP+cpkM, cpEtherAddress, &_bssid,
            cpEnd) < 0)
        return -1;
    return 0;
}

Packet *
BSSIDFilter::simple_action(Packet *p)
{
    const u_char *bssid = NULL;
    if (wifi_extract_addrs(p->data(), p->length(), NULL, NULL, NULL, NULL, &bssid) == -1)
        return p;

    if (bssid == NULL)
        return p;

    if (EtherAddress(bssid) == _bssid) {
        checked_output_push(1, p);
        return NULL;
    } else {
        return p;
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(BSSIDFilter)
