/*
 * pktparse_wrap.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include <clicknet/wifi.h>
#include <click/packet_anno.hh>
#include <pcap/pcap.h>
#include "pktparse_wrap.hh"
CLICK_DECLS

int
pktparse_click_packet(const Packet *p, int dlt, struct packet *pkt)
{
    struct pcap_pkthdr h;
    h.ts = p->timestamp_anno().timeval();
    h.caplen = p->length();
    h.len = p->length();

    int flags = PKTPARSE_IGNORE_BADLLC;

    if (dlt == DLT_IEEE802_11) {
        click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
        if (ceh->magic == WIFI_EXTRA_MAGIC) {
            if (ceh->flags & WIFI_EXTRA_DATAPAD)
                flags |= PKTPARSE_HAS_80211_PADDING;
            if (ceh->flags & WIFI_EXTRA_HAS_FCS)
                flags |= PKTPARSE_HAS_FCS;
        }
    }

    return pktparse_parse(&h, p->data(), dlt, pkt, flags);
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(PktParse)
// hard-coded paths suck, but I don't know how else to do this.
// "-rpath=$HOME/lib" doesn't work because gmake parses it wrong, and
// "-rpath=$(HOME)/lib" doesn't work because click-buildtool gets confused by
// the parentheses
ELEMENT_LIBS(-L=~/lib -rpath=/usr/home/ianrose/lib -lpktparse)
