#ifndef CLICK_WIFIUTIL_HH
#define CLICK_WIFIUTIL_HH

#include <click/string.hh>
#include <net80211/ieee80211.h>
CLICK_DECLS


// Timestamp (8 bytes), Beacon Interval (2 bytes), Capability Info (2 bytes)
#define IEEE80211_BEACON_FIXEDARGS 12

// not defined in my net80211/ieee80211.h
#ifndef IEEE80211_FC0_SUBTYPE_BA
#define IEEE80211_FC0_SUBTYPE_BA 0x90
#endif

// these values should match the ones in lu_encryptions in the database
#define WIFI_ENCRYPTION_WEP        1
#define WIFI_ENCRYPTION_TKIP       2
#define WIFI_ENCRYPTION_CCMP       4
#define WIFI_ENCRYPTION_PSK        8
#define WIFI_ENCRYPTION_8021X     16
#define WIFI_ENCRYPTION_VENDOR   256
#define WIFI_ENCRYPTION_UNKNOWN  512

/*
 * Method Declarations
 */

uint32_t wifi_calc_crc32(const uint8_t *data, size_t len);

String wifi_cipher_desc(int cipher);

String wifi_escape_ssid(const String&);

int wifi_extract_addrs(const u_char *frame, size_t len, const u_char **sa,
    const u_char **ta, const u_char **da, const u_char **ra,
    const u_char **bssid);

int wifi_extract_ethertype(const u_char *frame, size_t len, uint16_t *ethertype);

// does NOT include trailing FCS, nor the "payload" of management frames
size_t wifi_header_len(const u_char*);

inline bool wifi_parse_bcnint(const u_char*, size_t, int*);

inline bool wifi_parse_capinfo(const u_char*, size_t, int*);

// returns true iff either the RSN or WPA information element was present and
// well-formed
bool wifi_parse_ciphers(const u_char *frame, uint8_t len, uint32_t oui,
    int *group, int *unicast, int *key_mgmt);

bool wifi_parse_infoelt(const u_char*, size_t, uint8_t, uint8_t*, const u_char**);

bool wifi_parse_infoelt_vendor(const u_char*, size_t, uint8_t*, const u_char**, uint32_t);

inline bool wifi_parse_ssid(const u_char*, size_t, String*);


/*
 * Definitions of inlined functions
 */

bool
wifi_parse_bcnint(const u_char *frame, size_t len, int *ival)
{
    // this works on both beacons and probe request frames
    size_t hl = wifi_header_len(frame);
    if (len < (hl + IEEE80211_BEACON_FIXEDARGS)) return false;
    const u_char *mgmt_header = frame + hl;
    *ival = IEEE80211_BEACON_INTERVAL(mgmt_header);
    return true;
}

bool
wifi_parse_capinfo(const u_char *frame, size_t len, int *cap)
{
    // this works on both beacons and probe request frames
    size_t hl = wifi_header_len(frame);
    if (len < (hl + IEEE80211_BEACON_FIXEDARGS)) return false;
    const u_char *mgmt_header = frame + hl;
    *cap = IEEE80211_BEACON_CAPABILITY(mgmt_header);
    return true;
}

bool
wifi_parse_ssid(const u_char *frame, size_t len, String *ssid)
{
    uint8_t elen;
    const u_char *elt;
    if (!wifi_parse_infoelt(frame, len, IEEE80211_ELEMID_SSID, &elen, &elt))
        return false;
    *ssid = String((const char*)elt, elen);
    return true;
}

CLICK_ENDDECLS
#endif
