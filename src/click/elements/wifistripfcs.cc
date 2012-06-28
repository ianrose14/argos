/*
 * wifistripfcs.{cc,hh} -- strip any trailing FCS from 802.11 frames.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifistripfcs.hh"
#include <click/confparse.hh>
#include <clicknet/wifi.h>
#include <click/packet_anno.hh>
CLICK_DECLS


WifiStripFCS::WifiStripFCS() : _has_anno(false)
{
}

WifiStripFCS::~WifiStripFCS()
{
}

int
WifiStripFCS::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "ANNO", cpkC, &_has_anno, cpByte, &_anno,
            cpEnd) < 0)
        return -1;
    return 0;
}

Packet *
WifiStripFCS::simple_action(Packet *p)
{
    if (_has_anno) bzero(p->anno_u8() + _anno, 4);

    struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
    if (ceh->magic == WIFI_EXTRA_MAGIC) {
        if (ceh->flags & WIFI_EXTRA_HAS_FCS) {
            if (EXTRA_LENGTH_ANNO(p) >= 4) {
                SET_EXTRA_LENGTH_ANNO(p, EXTRA_LENGTH_ANNO(p) - 4);
            } else {
                size_t l = 4 - EXTRA_LENGTH_ANNO(p);
                
                if (_has_anno && (l == 4))
                    memcpy(p->anno_u8() + _anno, p->data() + p->length() - 4, 4);
                SET_EXTRA_LENGTH_ANNO(p, 0);
                p->take(l);
            }

            ceh->flags &= ~WIFI_EXTRA_HAS_FCS;
        }
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiStripFCS)
