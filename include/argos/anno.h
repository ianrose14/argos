/*
 * <argos/anno.h> - defines for Argos packet annotations
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#ifndef _ARGOS_ANNO_H_
#define _ARGOS_ANNO_H_

#include <click/packet_anno.hh>

/*
 * Unfortunately, this header has to be parsable by other tools (besides the c
 * compiler) so that they can read these constants.  This means that we can't
 * simply define ARGOS_SNIFF_ANNO_SIZE to be "sizeof(struct argos_sniff)" but
 * instead need to calculate it by hand (and make sure to update this value
 * whenever the contents of the struct change!).
 */
#define ARGOS_SNIFF_ANNO_OFFSET 40
#define ARGOS_SNIFF_ANNO_SIZE 8  /* 2+1+1+4 */
#define ARGOS_SNIFF_MAGIC  0x1978
#define ARGOS_SNIFF_ANNO(p) ((struct argos_sniff *) ((p)->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET))

struct argos_sniff {
    uint16_t magic;    /* used to confirm annotation contents */
    uint8_t channel;      /* 0 if unknown */
    uint8_t flags;

    /* IPv4 address of the MESH interface of the packet sniffer */
    struct in_addr sniffer;
} CLICK_SIZE_PACKED_ATTRIBUTE;


#define ARGOS_CTRL_ANNO_OFFSET 40
#define ARGOS_CTRL_ANNO_SIZE 8  /* 4+2+2 */
#define ARGOS_CTRL_MAGIC  0xED209AAA
#define ARGOS_CTRL_ANNO(p) ((struct argos_ctrl *) ((p)->anno_u8() + ARGOS_CTRL_ANNO_OFFSET))

// annotation denoting an Argos control message wrapped in a packet
struct argos_ctrl {
    uint32_t magic;    /* used to confirm annotation contents */
    uint16_t type;
    uint16_t subtype;
} CLICK_SIZE_PACKED_ATTRIBUTE;

/* type values */
enum {
    ARGOS_CTRL_ANNO_OVERLAY_TYPE=1
};

/*
 * We use bytes 24-27 to store the location of the WifiMerge header (expressed
 * as negative offset from the mac header), if there is one.  If there is no
 * WifiMerge header, the value 0 is stored instead as a flag.  This annotation
 * clobbers the EXTRA_PACKETS and REV_RATE annotations.
 */
#define WIFIMERGE_NOT_PRESENT    0
#define WIFIMERGE_ANNO_OFFSET    24
#define WIFIMERGE_ANNO_SIZE      4
#define WIFIMERGE_ANNO(p)        ((p)->anno_u32(WIFIMERGE_ANNO_OFFSET))
#define SET_WIFIMERGE_ANNO(p,v)  ((p)->set_anno_u32(WIFIMERGE_ANNO_OFFSET, (v)))

/*
 * We use byte 27 to store the TTL (in hops) of an Argos message.  This
 * annotation clobbers the GRID_ROUTE_CB annotation.
 */
#define TTL_ANNO_OFFSET      27
#define TTL_ANNO_SIZE        1
#define TTL_ANNO(p)          ((p)->anno_u8(TTL_ANNO_OFFSET))
#define SET_TTL_ANNO(p,v)    ((p)->set_anno_u8(TTL_ANNO_OFFSET, (v)))

#endif /* !_ARGOS_ANNO_H_ */

