/*
 * checkwifi.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "checkwifi.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/wifi.h>
#include <net80211/ieee80211.h>
#include "wifiutil.hh"
CLICK_DECLS

// not defined in my version of net80211/ieee80211.h
#ifndef IEEE80211_FC0_SUBTYPE_BA
#define IEEE80211_FC0_SUBTYPE_BA 0x90
#endif

/*
 * Source of specification (in particular, the field required in each management
 * frame):
 *
 * IEEE 802.11-2007 IEEE Standard for Information technology-Telecommunications
 * and information exchange between systems-Local and metropolitan area
 * networks-Specific requirements - Part 11: Wireless LAN Medium Access Control
 * (MAC) and Physical Layer (PHY) Specifications
 *
 * downloaded from http://standards.ieee.org/getieee802/download/802.11-2007.pdf
 */

CheckWifi::CheckWifi() : _drops(0), _verbose(false)
{
}

CheckWifi::~CheckWifi()
{
}

enum { H_DROPS, H_RESET };

void
CheckWifi::add_handlers()
{
    add_data_handlers("drops", Handler::OP_READ, &_drops);
    add_write_handler("reset", write_handler, (void*)H_RESET);
}

int
CheckWifi::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "VERBOSE", cpkP, cpBool, &_verbose,
            cpEnd) < 0)
        return -1;
    return 0;
}

Packet *
CheckWifi::simple_action(Packet *p)
{
    const u_char *data = p->data();
    const struct ieee80211_frame *wifi = (const struct ieee80211_frame*)data;
    uint8_t type, subtype, dir;
    size_t reqlen;
    size_t len = p->length();
    const char *desc = NULL;

    // make sure there are at least enough bytes to read the frame control field
    // (2 bytes)
    if (len < 2) {
        if (_verbose) click_chatter("%{element}: packet too short (%d)", this, len);
        goto drop;
    }

    type = wifi->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wifi->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    dir = wifi->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    // check 802.11 version
    if ((wifi->i_fc[0] & IEEE80211_FC0_VERSION_MASK) != IEEE80211_FC0_VERSION_0) {
        if (_verbose) click_chatter("%{element}: invalid 802.11 version (%d)", this,
            wifi->i_fc[0] & IEEE80211_FC0_VERSION_MASK);
        goto drop;  // bad version
    }

    // check lengths

    switch (type) {
    case IEEE80211_FC0_TYPE_MGT:
        // all management frames should have an 802.11 header of 24 bytes
        reqlen = sizeof(struct ieee80211_frame);

        if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) {
            desc = "AssocReq";
            if (validate_assocreq(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
            desc = "AssocResp";
            if (validate_assocresp(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
            desc = "ReassocReq";
            if (validate_reassocreq(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP) {
            desc = "ReassocResp";
            if (validate_reassocresp(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
            desc = "ProbeReq";
            if (validate_probereq(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
            desc = "ProbeResp";
            if (validate_proberesp(wifi, len) == false)
                goto drop;
            // grab the privacy bit from the Capability field
            int capinfo;
            if (!wifi_parse_capinfo(data, len, &capinfo))
                goto drop;
            if (capinfo & IEEE80211_CAPINFO_PRIVACY) {
                if (validate_cipher_elts(data, len) == false)
                    goto drop;
            }
        } else if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
            desc = "Beacon";
            if (validate_beacon(wifi, len) == false)
                goto drop;
            // grab the privacy bit from the Capability field
            int capinfo;
            if (!wifi_parse_capinfo(data, len, &capinfo))
                goto drop;
            if (capinfo & IEEE80211_CAPINFO_PRIVACY) {
                if (validate_cipher_elts(data, len) == false)
                    goto drop;
            }
        } else if (subtype == IEEE80211_FC0_SUBTYPE_ATIM) {
            desc = "ATIM";
            // from spec: "The frame body of a management frame of subtype ATIM
            // is null." but we do not check this as vendors may stick in other
            // fields and we don't care to report that as an error
        } else if (subtype == IEEE80211_FC0_SUBTYPE_DISASSOC) {
            desc = "Disassoc";
            if (validate_disassoc(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_AUTH) {
            desc = "Auth";
            if (validate_auth(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_DEAUTH) {
            desc = "Deauth";
            if (validate_deauth(wifi, len) == false)
                goto drop;
        } else if (subtype == IEEE80211_FC0_SUBTYPE_ACTION) {
            desc = "Action";
            // I don't care to validate these
        }
        else {
            if (_verbose) click_chatter("%{element}: invalid MGT subtype (x%02X)",
                this, subtype);
            goto drop;  // bad management-frame subtype
        }
        break;
    case IEEE80211_FC0_TYPE_DATA:
        desc = "Data";

        // all WDS frames should have an 802.11 header of 30 bytes (32 bytes for
        // QoS frames)
        if (dir == IEEE80211_FC1_DIR_DSTODS) {
            if (IEEE80211_QOS_HAS_SEQ(wifi))
                reqlen = sizeof(struct ieee80211_qosframe_addr4);
            else
                reqlen = sizeof(struct ieee80211_frame_addr4);
        } else {
            // all non-WDS data frames frames should have an 802.11 header of
            // 24 bytes (26 bytes for QoS frames)
            if (IEEE80211_QOS_HAS_SEQ(wifi))
                reqlen = sizeof(struct ieee80211_qosframe);
            else
                reqlen = sizeof(struct ieee80211_frame);
        }
        break;
    case IEEE80211_FC0_TYPE_CTL:
        if (subtype == IEEE80211_FC0_SUBTYPE_BAR) {
            desc = "BlockAckReq";
            reqlen = sizeof(struct ieee80211_frame_pspoll);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_BA) {
            desc = "BlockAck";
            reqlen = sizeof(struct ieee80211_frame_pspoll);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_PS_POLL) {
            desc = "PS-Poll";
            reqlen = sizeof(struct ieee80211_frame_pspoll);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_RTS) {
            desc = "RTS";
            reqlen = sizeof(struct ieee80211_frame_rts);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_CTS) {
            desc = "CTS";
            reqlen = sizeof(struct ieee80211_frame_cts);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_ACK) {
            desc = "ACK";
            reqlen = sizeof(struct ieee80211_frame_ack);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_CF_END) {
            desc = "CF-End";
            reqlen = sizeof(struct ieee80211_frame_cfend);
        } else if (subtype == IEEE80211_FC0_SUBTYPE_CF_END_ACK) {
            desc = "CF-End-ACK";
            reqlen = sizeof(struct ieee80211_frame_cfend);
        } else {
            if (_verbose) click_chatter("%{element}: invalid CTL subtype (x%02X)",
                this, subtype);
            goto drop;  // bad control-frame subtype
        }
        break;
    default:
        // bad frame type
        if (_verbose) click_chatter("%{element}: invalid frame type (x%02X)",
            this, type);
        goto drop;
    }

    if (len < reqlen) {
        if (_verbose)
            click_chatter("%{element}: %s frame too short (%d, requires %d)",
                this, desc, len, reqlen);
        goto drop;
    }

    return p;  // packet seems ok

drop:
    _drops++;
    checked_output_push(1, p);
    return NULL;
}

String
CheckWifi::read_handler(Element* e, void *thunk)
{
    const CheckWifi* elt = static_cast<CheckWifi*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_DROPS:
        return String(elt->_drops);
    default:
        return "internal error (bad thunk value)";
    } 
}

int
CheckWifi::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    CheckWifi* elt = static_cast<CheckWifi*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET: {
        elt->_drops = 0;
        return 0;
    }
    default:
        return errh->error("invalid thunk");
    }
}

#define validate_fixedelt(desc)                                         \
    do {                                                                \
        if (len < reqlen) {                                             \
            if (_verbose) {                                             \
                click_chatter("%{element}: packet too short (%d): %d bytes expected" \
                    " (for %s field)", this, len, reqlen, desc); \
            }                                                           \
            return false;                                               \
        }                                                               \
    } while (0);                                                        \
    
#define validate_infoelt(id, desc)                                      \
    do {                                                                \
        uint8_t *ptr = (uint8_t*)wifi;                                  \
        if (len < (reqlen+2)) {                                         \
            if (_verbose) {                                             \
                click_chatter("%{element}: packet too short (%d): >= %d bytes expected" \
                    " (for %s element)", this, len, reqlen+2, desc); \
            }                                                           \
            return false;                                               \
        }                                                               \
                                                                        \
        if (ptr[reqlen] != id) {                                        \
            /* ok now check if element is present at all */             \
            u_int i = reqlen;                                           \
            while (i < (len-1)) {                                       \
                if (ptr[i] == id) {                                     \
                    if (_verbose) {                                     \
                        click_chatter("%{element}: %s element (x%02x) out of order", \
                            this, desc, id);                  \
                    }                                                   \
                    return false;                                       \
                }                                                       \
                u_int nextlen = ptr[i+1] + 2;                           \
                i += nextlen;                                           \
            }                                                           \
            if (_verbose) {                                             \
                click_chatter("%{element}: %s element (x%02x) not present",     \
                    this, desc, id);                          \
            }                                                           \
            return false;                                               \
        }                                                               \
                                                                        \
        reqlen += (2 + ptr[reqlen+1]);                                  \
    } while (0)                                                         \
    

bool
CheckWifi::validate_assocreq(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Capability field
    validate_fixedelt("Capability");
    reqlen += 2;   // 2 byte Listen Interval field
    validate_fixedelt("Listen Interval");

    // SSID information element
    validate_infoelt(IEEE80211_ELEMID_SSID, "SSID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}

bool
CheckWifi::validate_assocresp(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Capability field
    validate_fixedelt("Capability");
    reqlen += 2;   // 2 byte Status Code field
    validate_fixedelt("Status Code");
    reqlen += 2;   // 2 byte AID field
    validate_fixedelt("AID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}
bool
CheckWifi::validate_auth(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Authentication Algorithm Num field
    validate_fixedelt("Authentication Algorithm Num");

    reqlen += 2;   // 2 byte Authentication Transaction SeqNum field
    validate_fixedelt("Authentication Transaction SeqNum");
    
    return true;
}

bool
CheckWifi::validate_beacon(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 8;   // 8 byte Timestamp field
    validate_fixedelt("Timestamp");
    reqlen += 2;   // 2 byte Beacon Interval field
    validate_fixedelt("Beacon Interval");
    reqlen += 2;   // 2 byte Capability field
    validate_fixedelt("Capability");

    // SSID information element
    validate_infoelt(IEEE80211_ELEMID_SSID, "SSID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}

bool
CheckWifi::validate_cipher_elts(const u_char *frame, size_t len) const
{
    int group, unicast, key_mgmt; 

    // first look for and validate any RSN information element that's present;
    // for efficiency, and to be a little bit less strict, we only parse
    // validate the first one if there are multiple (which would be odd)
    uint8_t elen;
    const u_char *elt;

    if (wifi_parse_infoelt(frame, len, IEEE80211_ELEMID_RSN, &elen, &elt)) {
        if (!wifi_parse_ciphers(elt, elen, RSN_OUI, &group, &unicast, &key_mgmt)) {
            if (_verbose) click_chatter("%{element}: invalid RSN element: %s",
                this, strerror(errno));
            return false;
        }
    }

    // next look for and validate any WPA information element, which is a
    // "Vendor" information elements with a 4-byte header (consisting of the
    // 3-byte WPA OUI followed by a 1-byte type code), followed by the same data
    // format as an RSN element
    uint32_t head = WPA_OUI + (WPA_OUI_TYPE << 24);
    if (wifi_parse_infoelt_vendor(frame, len, &elen, &elt, head)) {
        if (!wifi_parse_ciphers(elt, elen, WPA_OUI, &group, &unicast, &key_mgmt)) {
            if (_verbose) click_chatter("%{element}: invalid WPA Vendor element: %s",
                this, strerror(errno));
            return false;
        }
    }

    return true;
}

bool
CheckWifi::validate_deauth(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Reason Code field
    validate_fixedelt("Reason Code");
    
    return true;
}

bool
CheckWifi::validate_disassoc(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Reason Code field
    validate_fixedelt("Reason Code");
    
    return true;
}

bool
CheckWifi::validate_probereq(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);

    // SSID information element
    validate_infoelt(IEEE80211_ELEMID_SSID, "SSID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}

bool
CheckWifi::validate_proberesp(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 8;   // 8 byte Timestamp field
    validate_fixedelt("Timestamp");
    reqlen += 2;   // 2 byte Beacon Interval field
    validate_fixedelt("Beacon Interval");
    reqlen += 2;   // 2 byte Capability field
    validate_fixedelt("Capability");

    // SSID information element
    validate_infoelt(IEEE80211_ELEMID_SSID, "SSID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}

bool
CheckWifi::validate_reassocreq(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Capability field
    validate_fixedelt("Capability");
    reqlen += 2;   // 2 byte Listen Interval field
    validate_fixedelt("Listen Interval");
    reqlen += 6;   // 6 byte Current AP Address field
    validate_fixedelt("Current AP Address");

    // SSID information element
    validate_infoelt(IEEE80211_ELEMID_SSID, "SSID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}

bool
CheckWifi::validate_reassocresp(const struct ieee80211_frame *wifi, size_t len) const
{
    // no validation possible on encrypted frames; assume they are well-formed
    if (wifi->i_fc[1] & IEEE80211_FC1_WEP) return true;

    size_t reqlen = sizeof(struct ieee80211_frame);
    reqlen += 2;   // 2 byte Capability field
    validate_fixedelt("Capability");
    reqlen += 2;   // 2 byte Status Code field
    validate_fixedelt("Status Code");
    reqlen += 2;   // 2 byte AID field
    validate_fixedelt("AID");

    // Supported Rates information element
    validate_infoelt(IEEE80211_ELEMID_RATES, "Supported Rates");
    
    return true;
}

#undef validate_fixedelt
#undef validate_infoelt

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(CheckWifi)
