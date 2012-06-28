/*
 * wifiutil.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include <click/straccum.hh>
#include <clicknet/llc.h>
#include <clicknet/wifi.h>
#include <stdio.h>
#include <errno.h>
#include "wifiutil.hh"
CLICK_DECLS

// this code copied/adapted from:
// http://www.cl.cam.ac.uk/research/srg/bluebook/21/crc/node6.html
// "Fast CRC32 in Software", Nikos Drakos
#define QUOTIENT 0x04c11db7
uint32_t
wifi_calc_crc32(const uint8_t *data, size_t len)
{
    static bool initialized = false;
    static uint32_t crctab[256];

    if (!initialized) {
        for (int i = 0; i < 256; i++) {
            uint32_t crc = i << 24;
            for (int j = 0; j < 8; j++) {
                if (crc & 0x80000000)
                    crc = (crc << 1) ^ QUOTIENT;
                else
                    crc = crc << 1;
            }
            crctab[i] = crc;
        }
        initialized = true;
    }

    uint32_t result;

    if (len < 4) {
        result = 0;
        memcpy(&result, data, len);
        return result;
    }

    result = *data++ << 24;
    result |= *data++ << 16;
    result |= *data++ << 8;
    result |= *data++;
    result = ~ result;
    len -=4;
    
    for (u_int i=0; i < len; i++)
        result = (result << 8 | *data++) ^ crctab[result >> 24];
    
    return ~result;
}
#undef QUOTIENT

String
wifi_cipher_desc(int cipher)
{
    switch (cipher) {
    case WIFI_ENCRYPTION_WEP:
        return String("WEP");
    case WIFI_ENCRYPTION_TKIP:
        return String("TKIP");
    case WIFI_ENCRYPTION_CCMP:
        return String("CCMP");
    case WIFI_ENCRYPTION_PSK:
        return String("PSK");
    case WIFI_ENCRYPTION_8021X:
        return String("802.1X");
    default:
        return String("??");
    }
}

String
wifi_escape_ssid(const String &ssid)
{
    // first check if the string has any non-printable characters, or
    // double-quotes (we disallow quotes because it screws up parsing of things
    // like: ssid="foo"bar") -- if so, then print the ENTIRE string as escaped
    // hex; otherwise, print the string normally
    for (int i=0; i < ssid.length(); i++) {
        if ((!isprint(ssid.data()[i])) || (ssid.data()[i] == '"'))
            return ssid.quoted_hex();
    }

    return ssid;
}

int
wifi_extract_addrs(const u_char *frame, size_t len, const u_char **sa,
    const u_char **ta, const u_char **da, const u_char **ra,
    const u_char **bssid)
{
    // need at least 2 bytes to read the Frame Control field
    if (len < 2) return 0;  // frame truncated;

    const struct ieee80211_frame *wifi = (const struct ieee80211_frame *)frame;
    uint8_t type = wifi->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    uint8_t dir = wifi->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    // in ALL 802.11 frames, addr1 is the receiver
    if (len < 10) return 0;  // frame truncated
    if (ra != NULL) *ra = wifi->i_addr1;

    if (type == IEEE80211_FC0_TYPE_CTL) {
        // in all control frames, addr1 is also the destination
        if (da != NULL) *da = wifi->i_addr1;

        // for PS-Poll frames, addr1 is also the BSSID
        if (subtype == IEEE80211_FC0_SUBTYPE_PS_POLL) {
            if (bssid != NULL) *bssid = wifi->i_addr1;
        }

        // some control frames also have an addr2 field
        if (len < 16) return 0;  // frame truncated

        if ((subtype == IEEE80211_FC0_SUBTYPE_BAR) ||
            (subtype == IEEE80211_FC0_SUBTYPE_BA) ||
            (subtype == IEEE80211_FC0_SUBTYPE_RTS) ||
            (subtype == IEEE80211_FC0_SUBTYPE_PS_POLL) ||
            (subtype == IEEE80211_FC0_SUBTYPE_CF_END) ||
            (subtype == IEEE80211_FC0_SUBTYPE_CF_END_ACK)) {
            if (ta != NULL) *ta = wifi->i_addr2;
            if (sa != NULL) *sa = wifi->i_addr2;
        }

        // for CF-End and CF-End-Ack frames, addr2 is also the BSSID
        if ((subtype == IEEE80211_FC0_SUBTYPE_CF_END) ||
            (subtype == IEEE80211_FC0_SUBTYPE_CF_END_ACK)) {
            if (bssid != NULL) *bssid = wifi->i_addr2;
        }
        
        return 1;
    }

    if ((type != IEEE80211_FC0_TYPE_DATA) && (type != IEEE80211_FC0_TYPE_MGT)) {
        errno = EINVAL;
        return -1;  // invalid type field
    }

    // management and data frames follow the same address layouts (although
    // management frames only ever fall under the 'NoDS' direction category)

    switch (dir) {
    case IEEE80211_FC1_DIR_NODS:
        // IBSS frames have:
        // addr1 = receiver address (destination address)
        // addr2 = transmitter address (source address)
        // addr3 = BSSID
        if (da != NULL) *da = wifi->i_addr1;
        if (ta != NULL) *ta = wifi->i_addr2;
        if (sa != NULL) *sa = wifi->i_addr2;
        if (bssid != NULL) *bssid = wifi->i_addr3;
        break;
    case IEEE80211_FC1_DIR_TODS:
        // station-to-AP frames have:
        // addr1 = receiver address (BSSID)
        // addr2 = transmitter address (source address)
        // addr3 = destination address
        if (bssid != NULL) *bssid = wifi->i_addr1;
        if (ta != NULL) *ta = wifi->i_addr2;
        if (sa != NULL) *sa = wifi->i_addr2;
        if (da != NULL) *da = wifi->i_addr3;
        break;
    case IEEE80211_FC1_DIR_FROMDS:
        // AP-to-station frames have:
        // addr1 = receiver address (destination)
        // addr2 = transmitter address (BSSID)
        // addr3 = source address
        if (da != NULL) *da = wifi->i_addr1;
        if (ta != NULL) *ta = wifi->i_addr2;
        if (bssid != NULL) *bssid = wifi->i_addr2;
        if (sa != NULL) *sa = wifi->i_addr3;
        break;
    case IEEE80211_FC1_DIR_DSTODS: {
        // WDS (bridge) frame:
        // addr1 = receiver address
        // addr2 = transmitter address
        // addr3 = destination address (aka final receiver)
        // addr4 = source address (aka original transmitter)
        if (ta != NULL) *ta = wifi->i_addr2;
        if (da != NULL) *da = wifi->i_addr3;

        if (IEEE80211_QOS_HAS_SEQ(wifi)) {
            if (len < sizeof(struct ieee80211_qosframe_addr4)) return 0;  // frame truncated
            struct ieee80211_qosframe_addr4 *wds =
                (struct ieee80211_qosframe_addr4*)wifi;
            if (sa != NULL) *sa = wds->i_addr4;
        } else {
            if (len < sizeof(struct ieee80211_frame_addr4)) return 0;  // frame truncated
            struct ieee80211_frame_addr4 *wds =
                (struct ieee80211_frame_addr4*)wifi;
            if (sa != NULL) *sa = wds->i_addr4;
        }
        break;
    }
    default:
        // should never happen (invalid wifi packet direction)
        errno = EINVAL;
        return -1;
    }

    return 1;  // packet not truncated
}

int
wifi_extract_ethertype(const u_char *frame, size_t len, uint16_t *ethertype)
{
    // need at least 2 bytes to read the Frame Control field
    if (len < 2) return 0;  // frame truncated;

    const struct ieee80211_frame *wifi = (const struct ieee80211_frame*)frame;
    uint8_t type = wifi->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    if (type != IEEE80211_FC0_TYPE_DATA) return -1;
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return -1;

    size_t hl = wifi_header_len(frame);
    if (len <= (hl + sizeof(struct click_llc))) return 0;  // frame truncated
    if (memcmp(WIFI_LLC_HEADER, frame + hl, WIFI_LLC_HEADER_LEN) == -1) return -1;

    const struct click_llc *llc = (const struct click_llc*)(frame + hl);
    *ethertype = ntohs(llc->llc_un.type_snap.ether_type);
    return 1;
}

size_t
wifi_header_len(const u_char *frame)
{
    const struct ieee80211_frame *wifi = (const struct ieee80211_frame*)frame;
    uint8_t type = wifi->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    if (type == IEEE80211_FC0_TYPE_CTL) {
        uint8_t subtype = wifi->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
        switch (subtype) {
        case IEEE80211_FC0_SUBTYPE_ACK:
            return sizeof(struct ieee80211_frame_ack);
        case IEEE80211_FC0_SUBTYPE_BAR:
            return sizeof(struct ieee80211_frame_bar);
        case IEEE80211_FC0_SUBTYPE_BA:
            // FC, Dur, RA, SA, BA-Ctl, BA-SeqCtl, ACK-Bitmap
            return sizeof(struct ieee80211_frame_min) + sizeof(struct ieee80211_ba_request) + 128;
        case IEEE80211_FC0_SUBTYPE_CTS:
            return sizeof(struct ieee80211_frame_cts);
        case IEEE80211_FC0_SUBTYPE_RTS:
            return sizeof(struct ieee80211_frame_rts);
        case IEEE80211_FC0_SUBTYPE_PS_POLL:
            return sizeof(struct ieee80211_frame_pspoll);
        case IEEE80211_FC0_SUBTYPE_CF_END:
        case IEEE80211_FC0_SUBTYPE_CF_END_ACK:
            return sizeof(struct ieee80211_frame_cfend);
        default:
            // bad subtype?
            return sizeof(struct ieee80211_frame_min);
        }
    }

    if ((wifi->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS) {
        if (IEEE80211_QOS_HAS_SEQ(wifi))
            return sizeof(struct ieee80211_qosframe_addr4);
        else
            return sizeof(struct ieee80211_frame_addr4);
    } else {
        if (IEEE80211_QOS_HAS_SEQ(wifi))
            return sizeof(struct ieee80211_qosframe);
        else
            return sizeof(struct ieee80211_frame);
    }
}

bool
wifi_parse_ciphers(const u_char *elt, uint8_t elen, uint32_t oui, int *group,
    int *unicast, int *key_mgmt)
{
    // format (all fields after version are optional):
    // version (2), group cipher (4), pairwise cipher count (2), pairwise
    // ciphers (4 each), AKM cipher count (2), AKM ciphers (4 each), RSN
    // capabilities (2), PMKID count (2), PMKID list (16 each)

    // confirm length for version, group cipher, pairwise cipher count
    if (elen < 8) {
        // malformed element (advertised length is too short)
        errno = EINVAL;
        return false;
    }

    uint32_t version, cse_null, cse_wep40, cse_wep104, cse_tkip, cse_ccmp,
        ase_8021x, ase_psk;

    if (oui == RSN_OUI) {
        version = RSN_VERSION;
        cse_null = RSN_CSE_NULL;
        cse_wep40 = RSN_CSE_WEP40;
        cse_wep104 = RSN_CSE_WEP104;
        cse_tkip = RSN_CSE_TKIP;
        cse_ccmp = RSN_CSE_CCMP;
        ase_8021x = RSN_ASE_8021X_UNSPEC;
        ase_psk = RSN_ASE_8021X_PSK;
    }
    else if (oui == WPA_OUI) {
        version = WPA_VERSION;
        cse_null = WPA_CSE_NULL;
        cse_wep40 = WPA_CSE_WEP40;
        cse_wep104 = WPA_CSE_WEP104;
        cse_tkip = WPA_CSE_TKIP;
        cse_ccmp = WPA_CSE_CCMP;
        ase_8021x = WPA_ASE_8021X_UNSPEC;
        ase_psk = WPA_ASE_8021X_PSK;
    }
    else {
        errno = EINVAL;
        return false;
    }

    uint16_t elt_version = le16_to_cpu(*((uint16_t*)elt));
    if (elt_version != version) {
        errno = EPROTO;
        return false;
    }

    // cipher format = OUT (3 bytes) + Code (1 byte)
    uint32_t group_cipher = *((uint32_t*)(elt + 2));  // byte order unchanged
    uint8_t group_code = group_cipher >> 24;

    // mask out high byte to check OUI (in the lower 3 bytes)
    if ((group_cipher & 0xFFFFFF) == oui) {
        if (group_code == cse_wep40)
            *group = WIFI_ENCRYPTION_WEP;
        else if (group_code == cse_wep104)
            *group = WIFI_ENCRYPTION_WEP;
        else if (group_code == cse_tkip)
            *group = WIFI_ENCRYPTION_TKIP;
        else if (group_code == cse_ccmp)
            *group = WIFI_ENCRYPTION_CCMP;
        else
            *group = WIFI_ENCRYPTION_UNKNOWN;
    } else {
        // must be some vendor-specific OUI
        *group = WIFI_ENCRYPTION_VENDOR;
    }

    uint16_t unicast_count = le16_to_cpu(*((uint16_t*)(elt+6)));

    if (elen < (6 + 4*unicast_count)) {
        // malformed element (advertised length is too short)
        errno = EINVAL;
        return false;
    }

    *unicast = 0;

    for (int i=0; i < unicast_count; i++) {
        const u_char *p = elt + (8 + 4*i);
        uint32_t unicast_cipher = *((uint32_t*)p);  // unchanged byte order
        uint8_t unicast_code = unicast_cipher >> 24;

        // mask out high byte to check OUI (in the lower 3 bytes)
        if ((unicast_cipher & 0xFFFFFF) != oui) {
            // must be some vendor-specific OUI
            *unicast += WIFI_ENCRYPTION_VENDOR;
        } else {
            // cipher's oui == [out]
            if (unicast_code == cse_null)  // null means "use the group cipher"
                *unicast += *group;
            else if (unicast_code == cse_wep40)
                *unicast += WIFI_ENCRYPTION_WEP;
            else if (unicast_code == cse_wep104)
                *unicast += WIFI_ENCRYPTION_WEP;
            else if (unicast_code == cse_tkip)
                *unicast += WIFI_ENCRYPTION_TKIP;
            else if (unicast_code == cse_ccmp)
                *unicast += WIFI_ENCRYPTION_CCMP;
            else
                *unicast += WIFI_ENCRYPTION_UNKNOWN;
        }
    }

    int offset = 8 + 4*unicast_count;
    uint16_t akm_count = le16_to_cpu(*((uint16_t*)(elt+offset)));
    *key_mgmt = 0;

    if (elen < (offset + 4*akm_count)) {
        // malformed element (advertised length is too short)
        errno = EINVAL;
        return false;
    }

    for (int i=0; i < akm_count; i++) {
        const u_char *p = elt + (offset + 2 + 4*i);
        uint32_t akm = *((uint32_t*)p);  // unchanged byte order
        uint8_t akm_code = akm >> 24;

        // mask out high byte to check OUI (in the lower 3 bytes)
        if ((akm & 0xFFFFFF) != oui) {
            // must be some vendor-specific OUI
            *key_mgmt = WIFI_ENCRYPTION_VENDOR;
        } else {
            // AKM's OUI == [oui]
            if (akm_code == ase_8021x)
                *key_mgmt = WIFI_ENCRYPTION_8021X;
            else if (akm_code == ase_psk)
                *key_mgmt = WIFI_ENCRYPTION_PSK;
            else
                *key_mgmt = WIFI_ENCRYPTION_UNKNOWN;
        }
    }

    return true;
}

bool
wifi_parse_infoelt(const u_char *frame, size_t len, uint8_t id, uint8_t *elt_len,
    const u_char **element)
{
    // this works on both beacons and probe request frames
    size_t hl = wifi_header_len(frame);
    if (len < hl) return false;

    const struct ieee80211_frame *wifi = (const struct ieee80211_frame *)frame;
    uint8_t type = wifi->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    if (type != IEEE80211_FC0_TYPE_MGT) return false;

    uint8_t subtype = wifi->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    
    size_t offset = hl;
    switch (subtype) {
    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
        offset += 4;  // CapInfo (2) + ListenInt (2)
        break;
    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        offset += 6;  // CapInfo (2) + StatusCode (2) + AssocId (2)
        break;
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
        offset += 10;  // CapInfo (2) + ListenInt (2) + CurrentAddress (6)
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
        offset += 0;
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
    case IEEE80211_FC0_SUBTYPE_BEACON:
        offset += IEEE80211_BEACON_FIXEDARGS;
        break;
    case IEEE80211_FC0_SUBTYPE_AUTH:
        offset += 6;  // AuthAlog (2) + AuthSeqno (2) + StatusCode (2)
        break;
    case IEEE80211_FC0_SUBTYPE_ATIM:
    case IEEE80211_FC0_SUBTYPE_DISASSOC:
    case IEEE80211_FC0_SUBTYPE_DEAUTH:
    case IEEE80211_FC0_SUBTYPE_ACTION:
        // quit early; these frame-types do not carry information elements
        return false;
    default:
        // invalid subtype
        return false;
    }

    while (offset < (len-1)) {
        size_t l = frame[offset+1];
        if (frame[offset] == id) {
            // found the right information element, but is it truncated?
            if ((offset + 2 + l) <= len) {
                *elt_len = l;
                *element = frame + offset + 2;
                return true;
            } else {
                return false;
            }
        }

        offset += 2 + l;
    }

    return false;
}

bool
wifi_parse_infoelt_vendor(const u_char *frame, size_t len, uint8_t *elt_len,
    const u_char **element, uint32_t header)
{
    // this works on both beacons and probe request frames
    size_t hl = wifi_header_len(frame);
    if (len < hl) return false;

    const struct ieee80211_frame *wifi = (const struct ieee80211_frame *)frame;
    uint8_t type = wifi->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    if (type != IEEE80211_FC0_TYPE_MGT) return false;

    uint8_t subtype = wifi->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    
    size_t offset = hl;
    switch (subtype) {
    case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
        offset += 4;  // CapInfo (2) + ListenInt (2)
        break;
    case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
    case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
        offset += 6;  // CapInfo (2) + StatusCode (2) + AssocId (2)
        break;
    case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
        offset += 10;  // CapInfo (2) + ListenInt (2) + CurrentAddress (6)
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
        offset += 0;
        break;
    case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
    case IEEE80211_FC0_SUBTYPE_BEACON:
        offset += IEEE80211_BEACON_FIXEDARGS;
        break;
    case IEEE80211_FC0_SUBTYPE_AUTH:
        offset += 6;  // AuthAlog (2) + AuthSeqno (2) + StatusCode (2)
        break;
    case IEEE80211_FC0_SUBTYPE_ATIM:
    case IEEE80211_FC0_SUBTYPE_DISASSOC:
    case IEEE80211_FC0_SUBTYPE_DEAUTH:
    case IEEE80211_FC0_SUBTYPE_ACTION:
        // quit early; these frame-types do not carry information elements
        return false;
    default:
        // invalid subtype
        return false;
    }

    while (offset < (len-1)) {
        size_t l = frame[offset+1];
        if (frame[offset] == IEEE80211_ELEMID_VENDOR) {
            // found the right information element, but is it truncated?
            if ((offset + 2 + l) <= len) {
                // check that header is complete
                if (l < 4) return false;

                // does this vendor infoelt have the header we want?
                uint32_t *intp = (uint32_t*)(frame + offset + 2);
                if (intp[0] == header) {
                    // strip off the leading 4 bytes (which make up the header)
                    *elt_len = l - 4;
                    *element = frame + offset + 2 + 4;
                    return true;
                }
            } else {
                return false;
            }
        }

        offset += 2 + l;
    }

    return false;
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(WifiUtil)
