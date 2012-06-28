/*
 * setsniffer.{cc,hh} -- push a set header onto packets.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "setsniffer.hh"
#include <click/confparse.hh>
#include "iputil.hh"
#include "nodeinfo.hh"
CLICK_DECLS


SetSniffer::SetSniffer()
{
    // initialize header to defaults (most fields default to 0)
    memset(&_hdr, '\0', sizeof(struct argos_sniff));
    _hdr.magic = ARGOS_SNIFF_MAGIC;
}

SetSniffer::~SetSniffer()
{
}

int
SetSniffer::configure(Vector<String> &conf, ErrorHandler *errh)
{
    uint8_t channel = 0;
    IPAddress ip;

    if (cp_va_kparse(conf, this, errh,
            "CHANNEL", 0, cpByte, channel,
            "SNIFFER", 0, cpIPAddress, &ip,
            cpEnd) < 0)
        return -1;

    _hdr.channel = channel;
    _hdr.sniffer = ip.in_addr();

    return 0;
}

Packet *
SetSniffer::simple_action(Packet *p)
{
    uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    memcpy(anno_ptr, &_hdr, sizeof(struct argos_sniff));
    SET_WIFIMERGE_ANNO(p, WIFIMERGE_NOT_PRESENT);
    return p;
}

int
SetSniffer::parse_sniffer_id(const Packet *p, int32_t *node_id, ErrorHandler *errh)
{
    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;

    if (sniff->magic != ARGOS_SNIFF_MAGIC)
        return errh->error("no ARGOS_SNIFF annotation present");
    
    IPAddress ip = IPAddress(sniff->sniffer);

    // special case
    if (ip == IPAddress(0)) {
        *node_id = 0;
        return 0;
    }

    int32_t *rv = NodeInfo::query_node_id(ip);
    if (rv == NULL)
        return errh->error("unknown sniffer IP: %s", ip.unparse().c_str());

    *node_id = *rv;
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetSniffer)
