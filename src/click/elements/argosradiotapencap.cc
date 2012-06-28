/*
 * argosradiotapencap.{cc,hh} -- encapsultates 802.11 packets
 *
 * Adapted from the original radiotapencap.{cc,hh} by John Bicket
 *
 * The major difference is that this version includes the 'Channel' radiotap
 * field, populating it with the value of the 'sniffer' field of the ARGOS_SNIFF
 * annotation.  This is because the radiotap header specification does not
 * provide any reasonable header fields to save the identity of the capturing
 * device/node.  In time it might be a good idea to instead save this data in a
 * Vendor Namespace (which is a new radiotap field proposal).
 */

#include <click/config.h>
#include "argosradiotapencap.hh"
#include <click/glue.hh>
#include <clicknet/wifi.h>
#include <click/packet_anno.hh>
#include <clicknet/radiotap.h>
#include "argos/anno.h"
CLICK_DECLS


#define ARGOS_RADIOTAP_PRESENT                    \
    (                                             \
     (1 << IEEE80211_RADIOTAP_FLAGS)		| \
     (1 << IEEE80211_RADIOTAP_RATE)		| \
     (1 << IEEE80211_RADIOTAP_CHANNEL)          | \
     (1 << IEEE80211_RADIOTAP_DBM_TX_POWER)	| \
     (1 << IEEE80211_RADIOTAP_RTS_RETRIES)	| \
     (1 << IEEE80211_RADIOTAP_DATA_RETRIES)	| \
     0)

struct argos_radiotap_header {
    struct ieee80211_radiotap_header wt_ihdr;
    u_int8_t  wt_flags;
    u_int8_t  wt_rate;
    u_int16_t wt_channel_freq;
    u_int16_t wt_channel_flags;
    u_int8_t  wt_txpower;
    u_int8_t  wt_rts_retries;
    u_int8_t  wt_data_retries;
};

ArgosRadiotapEncap::ArgosRadiotapEncap()
{
}

ArgosRadiotapEncap::~ArgosRadiotapEncap()
{
}

Packet *
ArgosRadiotapEncap::simple_action(Packet *p)
{
    WritablePacket *p_out = p->uniqueify();
    if (!p_out) {
        checked_output_push(1, p);
        return NULL;
    }

    struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p_out);
    if (ceh->magic != WIFI_EXTRA_MAGIC) {
        click_chatter("%{element}: no WIFI_EXTRA annotation present", this);
        checked_output_push(1, p);
        return NULL;
    }

    struct argos_sniff *sniff = ARGOS_SNIFF_ANNO(p_out);
    if (sniff->magic != ARGOS_SNIFF_MAGIC) {
        click_chatter("%{element}: no ARGOS_SNIFF annotation present", this);
        checked_output_push(1, p);
        return NULL;
    }

    p_out = p_out->push(sizeof(struct argos_radiotap_header));

    if (p_out) {
        struct argos_radiotap_header *arh = (struct argos_radiotap_header *)p_out->data();
        bzero(arh, sizeof(struct argos_radiotap_header));

        arh->wt_ihdr.it_version = 0;
        arh->wt_ihdr.it_len = sizeof(struct argos_radiotap_header);
        arh->wt_ihdr.it_present = ARGOS_RADIOTAP_PRESENT;

        arh->wt_rate = ceh->rate;
        uint32_t ip = cpu_to_le32(sniff->sniffer.s_addr);
        memcpy(&(arh->wt_channel_freq), &ip, 4);
        arh->wt_txpower = ceh->power;
        arh->wt_rts_retries = 0;
        if (ceh->max_tries > 0) {
            arh->wt_data_retries = ceh->max_tries - 1;
        }
        if (ceh->flags & WIFI_EXTRA_HAS_FCS)
            arh->wt_flags |= IEEE80211_RADIOTAP_F_FCS;
        if (ceh->flags & WIFI_EXTRA_DATAPAD)
            arh->wt_flags |= IEEE80211_RADIOTAP_F_DATAPAD;
    }

    return p_out;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ArgosRadiotapEncap)
