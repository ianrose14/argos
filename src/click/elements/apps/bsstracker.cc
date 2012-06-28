/*
 * bsstracker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "bsstracker.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include "../wifiutil.hh"
CLICK_DECLS

inline static bool all_nulls(const String&);

BSSTracker::BSSTracker()
    : _db(NULL), _log(NULL)
{
}

BSSTracker::~BSSTracker()
{
    if (_log != NULL) delete _log;
}

enum { H_BSS_COUNT, H_DUMP_ALL };

void
BSSTracker::add_handlers()
{
    add_read_handler("bss_count", read_handler, (void*)H_BSS_COUNT);
    add_read_handler("dump_all", read_handler, (void*)H_DUMP_ALL);
}

int
BSSTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "DB", 0, cpElement, &elt,
            "LOGGING", 0, cpString, &loglevel,
            "NETLOG", 0, cpString, &netlog,
            "LOGGER", 0, cpString, &logelt,
            cpEnd) < 0)
        return -1;

    // create log before anything else
    _log = LogHandler::get_logger(this, NULL, loglevel.c_str(), netlog.c_str(),
        logelt.c_str(), errh);
    if (_log == NULL)
        return -EINVAL;

    // check that elt is a pointer to a PostgreSQL element (if specified at all)
    if (elt != NULL) {
        _db = (PostgreSQL*)elt->cast("PostgreSQL");
        if (_db == NULL)
            return errh->error("DB element is not an instance of type PostgreSQL");
    }

    return 0;
}

int
BSSTracker::initialize(ErrorHandler *errh)
{
    if (_db != NULL) {
        String sql = "select bssid, ssid, ssid_changed, ssid_in_beacons"
            ", channels, bcn_int, is_ibss, encryption_types, group_cipher"
            " from bss_stats";
        PGresult *result = _db->db_select(sql);
        if (result == NULL)
            return errh->error("failed to select from bss_stats (PGresult was NULL)");

        int nrows = PQntuples(result);
        for (int i=0; i < nrows; i++) {
            EtherAddress bssid;
            BSSInfo info;

            String val = String(PQgetvalue(result, i, 0));
            if (!cp_ethernet_address(val, &bssid, this))
                return errh->error("failed to parse bssid from database: %s", val.c_str());

            info.ssid = String(PQgetvalue(result, i, 1));

            char *s = PQgetvalue(result, i, 2);
            info.ssid_changed = (strtol(s, NULL, 10) != 0);

            s = PQgetvalue(result, i, 3);
            info.ssid_in_beacons = (strtol(s, NULL, 10) != 0);

            s = PQgetvalue(result, i, 4);
            info.channels = (int)strtol(s, NULL, 10);

            s = PQgetvalue(result, i, 5);
            info.bcn_int = (int)strtol(s, NULL, 10);

            s = PQgetvalue(result, i, 6);
            info.is_ibss = (strtol(s, NULL, 10) != 0);

            s = PQgetvalue(result, i, 7);
            info.encryption_types = (int)strtol(s, NULL, 10);

            s = PQgetvalue(result, i, 8);
            info.group_cipher = (int)strtol(s, NULL, 10);

            _bss_map.insert(bssid, info);
        }

        PQclear(result);
    }

    return 0;
}

void
BSSTracker::push(int, Packet *p)
{
    const struct click_wifi *wifi = (const struct click_wifi *)p->data();

    // all management frames should at least have all of the fields in the
    // click_wifi struct
    if (p->length() < sizeof(struct click_wifi)) {
        p->kill();
        return;
    }

    // look for beacons and probe-responses only
    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    if (type != WIFI_FC0_TYPE_MGT) {
        p->kill();
        return;
    }

    if ((subtype != WIFI_FC0_SUBTYPE_BEACON) && (subtype != WIFI_FC0_SUBTYPE_PROBE_RESP)) {
        p->kill();
        return;
    }

    // in Beacon and ProbeResponse frames, addr2 = SRC and addr3 = BSSID
    EtherAddress src = EtherAddress(wifi->i_addr2);
    EtherAddress bssid = EtherAddress(wifi->i_addr3);
    if (bssid.is_broadcast()) {
        // don't know any reason that this should occur
        _log->warning("BSSID %s: rejecting packet (invalid BSSID)",
            bssid.unparse_colon().c_str());
        checked_output_push(1, p);
        return;
    }

    String ssid;
    if (!wifi_parse_ssid(p->data(), p->length(), &ssid)) {
        // packet truncated or malformed
        _log->debug("BSSID %s: rejecting packet (no SSID element)",
            bssid.unparse_colon().c_str());
        checked_output_push(1, p);
        return;
    }

    // SSIDs of all NULL characters are technically protocol compliant (because
    // there are no restrictions on what characters can be used) but they are
    // often used as a crappy form of SSID-hiding so strip them
    if (all_nulls(ssid))
        ssid = "";

    int bcn_int;
    if (!wifi_parse_bcnint(p->data(), p->length(), &bcn_int)) {
        // packet truncated or malformed
        _log->debug("BSSID %s: rejecting packet (no BeaconInt element)",
            bssid.unparse_colon().c_str());
        checked_output_push(1, p);
        return;
    }

    int capinfo;
    if (!wifi_parse_capinfo(p->data(), p->length(), &capinfo)) {
        // packet truncated or malformed
        _log->debug("BSSID %s: rejecting packet (no CapInfo element)",
            bssid.unparse_colon().c_str());
        checked_output_push(1, p);
        return;
    }

    bool is_ibss = capinfo & WIFI_CAPINFO_IBSS;

    // Sometimes I see probe-response messages with bssid <X> from an AP that
    // ISN'T in that bss - I have only noticed this with our own CM9 radios so
    // perhaps its an Ath driver bug or something.  Regardless, as a workaround
    // we treat all (non-IBSS) probe request frames with the src (AP) address !=
    // the bssid address as "suspicious", meaning they are not allowed to
    // override any existing data.
    bool suspicious_packet = (subtype == WIFI_FC0_SUBTYPE_PROBE_RESP) && (src != bssid) && (!is_ibss);

    if (suspicious_packet)
        _log->debug("packet is suspicious (ProbeResp with src=%s and bssid=%s)",
            src.unparse_colon().c_str(), bssid.unparse_colon().c_str());

    uint8_t channel = 0;
    uint8_t elt_len;
    const u_char *elt;
    if (wifi_parse_infoelt(p->data(), p->length(), WIFI_ELEMID_DSPARMS, &elt_len, &elt)) {
        // sanity check
        if (elt_len != 1) {
            _log->info("invalid packet received with DS-Params InfoElt of length %d", 
                elt_len);
            if (noutputs() > 1) {
                Packet *q = p->clone();
                if (q) output(1).push(q);
            }
        } else {
            channel = elt[0];
        }
    }

    bool got_ciphers;
    int group_cipher=0, unicast_cipher=0, key_mgmt=0;

    // if a BSS supports *any* kind of encryption, the Privacy bit should be
    // enabled in the Capability information element
    if (capinfo & IEEE80211_CAPINFO_PRIVACY) {
        // first look for an RSN information element
        uint8_t elen;
        const u_char *elt;
        if (wifi_parse_infoelt(p->data(), p->length(), IEEE80211_ELEMID_RSN, &elen, &elt)) {
            got_ciphers = wifi_parse_ciphers(elt, elen, RSN_OUI, &group_cipher,
                &unicast_cipher, &key_mgmt);

            if (!got_ciphers) {
                _log->info("BSSID %s: RSN element parsing failed (%s)",
                    bssid.unparse_colon().c_str(), strerror(errno));
                if (noutputs() > 1) {
                    Packet *q = p->clone();
                    if (q) output(1).push(q);
                }
            }
        }

        if (!got_ciphers) {
            // if no RSN information element was found (or parsing failed),
            // check for a WPA element -- in *most* cases, APs will advertise
            // both RSN and WPA information elements (making this second check
            // unnecessary), but I have seen a few cases where a WPA element is
            // present but not an RSN element
            uint32_t head = WPA_OUI + (WPA_OUI_TYPE << 24);
            if (wifi_parse_infoelt_vendor(p->data(), p->length(), &elen, &elt, head)) {
                got_ciphers = wifi_parse_ciphers(elt, elen, WPA_OUI, &group_cipher,
                    &unicast_cipher, &key_mgmt);

                if (!got_ciphers) {
                    _log->info("BSSID %s: WPA element parsing failed (%s)",
                        bssid.unparse_colon().c_str(), strerror(errno));
                    if (noutputs() > 1) {
                        Packet *q = p->clone();
                        if (q) output(1).push(q);
                    }
                }
            }
        }

        if (!got_ciphers) {
            // no WPA element either - I assume in this case that the BSS only
            // supports WEP (must be an old AP!)
            got_ciphers = true;
            unicast_cipher = WIFI_ENCRYPTION_WEP;
            group_cipher = WIFI_ENCRYPTION_WEP;
            key_mgmt = WIFI_ENCRYPTION_PSK;
        }
    }

    bool emit_packet = false;

    BSSInfo *info = _bss_map.findp(bssid);
    if (info == NULL) {
        // new BSS
        BSSInfo new_info;
        new_info.ssid = ssid;
        new_info.is_ibss = is_ibss;
        new_info.ssid_changed = 0;
        new_info.ssid_in_beacons = ((ssid.length() > 0) && (subtype == WIFI_FC0_SUBTYPE_BEACON));
        new_info.channels = 1 << (channel-1);
        new_info.bcn_int = bcn_int;
        new_info.encryption_types = unicast_cipher + key_mgmt;
        new_info.group_cipher = group_cipher;

        _bss_map.insert(bssid, new_info);

        // todo - delete these messages?
        _log->data("NEW-BSS BSSID=%s SSID=\"%s\" ibss=%d",
            bssid.unparse_colon().c_str(), wifi_escape_ssid(ssid).c_str(),
            is_ibss);

        if (_db) db_insert_bss(bssid, &new_info);

        // always emit the packet when a new BSS is detected
        emit_packet = true;

    }
    // else there is an existing entry, but we only process it if this packet is
    // not 'suspicious' (see above)
    else if (!suspicious_packet) {
        // update existing entry
        bool updated = false;

        // If new SSID is empty, ignore it (an empty SSID in a beacon or
        // proberesp is NOT protocol compliant, but the BeaconScanner element
        // also performs this check so perhaps its a realistic danger?).
        // Also, if the SSID consists of all NULL characters, this is a "hidden"
        // SSID (which is not protocol compliant, but is common behavior) -
        // reading on the web indicates that most systems use 32 NULL
        // characters, but I have seen other lengths.  Since an AP may use its
        // "real" SSID in probe-responses and an SSID of all NULLs in beacons,
        // we need to ignore the "hidden" SSIDs, otherwise update messages will
        // constantly be emitted as the SSID that we have on record flip-flops
        // back and forth between the "real" and "hidden" SSID values
        if ((ssid != "") && (info->ssid.compare(ssid) != 0)) {
            if (info->ssid != "") {
                updated = true;

                // if this is the very first time that we have seen this BSS'
                // SSID change, we print a warning and push a copy of the packet
                // to output port 1; otherwise we update the SSID quietly
                if (info->ssid_changed) {
                    _log->debug("BSSID %s: ssid changed from \"%s\" to \"%s\"",
                        bssid.unparse_colon().c_str(), wifi_escape_ssid(ssid).c_str(),
                        wifi_escape_ssid(info->ssid).c_str());
                } else {
                    _log->info("BSSID %s: ssid changed from \"%s\" to \"%s\"",
                        bssid.unparse_colon().c_str(), wifi_escape_ssid(ssid).c_str(),
                        wifi_escape_ssid(info->ssid).c_str());

                    if (noutputs() > 1) {
                        Packet *q = p->clone();
                        if (q) output(1).push(q);
                    }
                }

                info->ssid = ssid;
                info->ssid_changed = 1;
            }
        }

        if (info->is_ibss != is_ibss) {
            _log->info("BSSID %s: changed from ibss=%d to ibss=%d",
                bssid.unparse_colon().c_str(), info->is_ibss, is_ibss);
            info->is_ibss = is_ibss;
            if (noutputs() > 1) {
                Packet *q = p->clone();
                if (q) output(1).push(q);
            }
        }

        bool ssid_in_beacons = (ssid.length() > 0) && (subtype == WIFI_FC0_SUBTYPE_BEACON);
        if (!info->ssid_in_beacons && ssid_in_beacons) {
            updated = true;
            info->ssid_in_beacons = 1;
        }

        int encr_types;

        // IBSS networks are untrustworthy; since there are multiple APs per BSS
        // they might advertise different parameters from each-other, so we skip
        // most consistency checks
        if (is_ibss) goto end_checks;

        if (channel >= 32) {
            _log->info("BSSID %s: ignoring invalid channel %d",
                bssid.unparse_colon().c_str(), channel);
        } else {
            uint32_t channel_mask = 1 << (channel-1);

            if ((info->channels & channel_mask) == 0) {
                updated = true;
                info->channels |= channel_mask;
            }
        }

        if (info->bcn_int != bcn_int) {
            _log->info("BSSID %s: changed from bcn_int=%d to bcn_int=%d",
                bssid.unparse_colon().c_str(), info->bcn_int, bcn_int);
            info->bcn_int = bcn_int;
            if (noutputs() > 1) {
                Packet *q = p->clone();
                if (q) output(1).push(q);
            }
        }

        encr_types = unicast_cipher + key_mgmt;
        if (encr_types & (~info->encryption_types)) {
            encr_types |= info->encryption_types;
            // only issue a warning if we DID know about some encryptions
            // previously, but now we have seen different ones
            if (info->encryption_types != 0) {
                _log->info("BSSID %s: changed from encr_types=%d to encr_types=%d",
                    bssid.unparse_colon().c_str(), info->encryption_types, encr_types);
                if (noutputs() > 1) {
                    Packet *q = p->clone();
                    if (q) output(1).push(q);
                }
            }
            updated = true;
            info->encryption_types = encr_types;
        }

        // group_cipher can be 0 if we simply haven't seen any beacons
        if ((group_cipher != info->group_cipher) && (group_cipher != 0)) {
            // only issue a warning if we DID know what the group encryption was
            // previously, but now we have seen a different one
            if (info->group_cipher != 0) {
                _log->info("BSSID %s: changed from group_cipher=%d to group_cipher=%d",
                    bssid.unparse_colon().c_str(), info->group_cipher, group_cipher);
                if (noutputs() > 1) {
                    Packet *q = p->clone();
                    if (q) output(1).push(q);
                }
            }
            updated = true;
            info->group_cipher = group_cipher;
        }

    end_checks:

        if (updated) {
            emit_packet = true;
            if (_db != NULL) db_update_bss(bssid, info);
        }
    }

    if (emit_packet)
        output(0).push(p);
    else
        p->kill();
}

void
BSSTracker::db_insert_bss(EtherAddress &bssid, BSSInfo *info)
{
    Vector<const char*> values;

    static const String query = String("INSERT INTO bss_stats"
        " (bssid, ssid, ssid_changed, ssid_in_beacons, channels, bcn_int"
        ", is_ibss, encryption_types, group_cipher, last_updated)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());");

    String ssid_changed = String((int)info->ssid_changed);
    String ssid_in_beacons = String((int)info->ssid_in_beacons);
    String channels = String((int)info->channels);
    String bcn_int = String((int)info->bcn_int);
    String is_ibss = String((int)info->is_ibss);
    String encryption_types = String((int)info->encryption_types);
    String group_cipher = String((int)info->group_cipher);

    // need to keep this variable around on the stack for a bit
    String bssid_str = bssid.unparse_colon();
    values.push_back(bssid_str.c_str());
    values.push_back(info->ssid.c_str());
    values.push_back(ssid_changed.c_str());
    values.push_back(ssid_in_beacons.c_str());
    values.push_back(channels.c_str());
    values.push_back(bcn_int.c_str());
    values.push_back(is_ibss.c_str());
    values.push_back(encryption_types.c_str());
    values.push_back(group_cipher.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0)
        _log->error("db_insert failed: %s", errh.get_last_error().c_str());
    else if (rv == 1)
        _log->debug("1 row inserted for BSSID %s", bssid.unparse_colon().c_str());
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for BSSID %s", rv,
            bssid.unparse_colon().c_str());
}

void
BSSTracker::db_update_bss(EtherAddress &bssid, BSSInfo *info)
{
    Vector<const char *> values;

    static const String query = String("UPDATE bss_stats"
        " set ssid=$1, ssid_changed=$2, ssid_in_beacons=$3, channels=$4"
        ", bcn_int=$5, is_ibss=$6, encryption_types=$7, group_cipher=$8"
        ", last_updated=now() WHERE bssid=$9;");

    String bssid_str = bssid.unparse_colon();
    String ssid_changed = String((int)info->ssid_changed);
    String ssid_in_beacons = String((int)info->ssid_in_beacons);
    String channels = String((int)info->channels);
    String bcn_int = String((int)info->bcn_int);
    String is_ibss = String((int)info->is_ibss);
    String encryption_types = String((int)info->encryption_types);
    String group_cipher = String((int)info->group_cipher);

    values.push_back(info->ssid.c_str());
    values.push_back(ssid_changed.c_str());
    values.push_back(ssid_in_beacons.c_str());
    values.push_back(channels.c_str());
    values.push_back(bcn_int.c_str());
    values.push_back(is_ibss.c_str());
    values.push_back(encryption_types.c_str());
    values.push_back(group_cipher.c_str());
    values.push_back(bssid_str.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0) {
        StringAccum sa;
        for (int i=0; i < values.size(); i++)
            sa << String(values[i]) << " | ";
        _log->error("db_update failed: %s  (args: %s)",
            errh.get_last_error().c_str(), sa.take_string().c_str());
    }
    else if (rv == 1)
        _log->debug("1 row updated for BSSID %s", bssid.unparse_colon().c_str());
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows affected by sql update for BSSID %s", rv,
            bssid.unparse_colon().c_str());
}

/*
 * STATIC METHODS
 */

String
BSSTracker::read_handler(Element *e, void *thunk)
{
    const BSSTracker *elt = static_cast<BSSTracker*>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_BSS_COUNT:
        return String(elt->_bss_map.size());
    case H_DUMP_ALL: {
        StringAccum sa;
        HashMap<EtherAddress, BSSInfo>::const_iterator iter = elt->_bss_map.begin();
        for (; iter != elt->_bss_map.end(); iter++) {
            sa << "BSSID=" << iter.key().unparse_colon()
               << " SSID=\"" << wifi_escape_ssid(iter.value().ssid)
               << "\" ibss=" << (uint32_t)iter.value().is_ibss;

            if (iter.value().encryption_types != 0)
                sa << " encryption-types=" << iter.value().encryption_types
                   << " group-cipher=" << iter.value().group_cipher;

            sa << "\n";
        }
        
        return sa.take_string();
    }
    default:
        return "internal error (bad thunk value)";
    }
}

// note that 0-length strings return true
inline static bool
all_nulls(const String &s)
{
    for (int i=0; i < s.length(); i++)
        if (s.data()[i] != '\0')
            return false;
    return true;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(BSSTracker)
