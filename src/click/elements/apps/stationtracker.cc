/*
 * stationtracker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "stationtracker.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include <net80211/ieee80211.h>
#include <unistd.h>
#include <sys/endian.h>  /* for be64toh and htobe64 which may not be portable */
#include "../loghandler.hh"
#include "../nodeinfo.hh"
#include "../wifiutil.hh"
CLICK_DECLS

// calculate seqnum gap from a to b, allowing small reorderings only if the
// out-of-order frame has the 'retry' flag set
#define WIFI_SEQNUM_DIFF(a,b,retry)                             \
    (((a) <= (b)) ?                                             \
        ((b) - (a)) :                                                   \
        (((((a) - (b)) < 3) && (retry)) ? 0 : ((b) + 4096 - (a))))

// somewhat arbitrary threshold for "close to 0"
#define WIFI_LITTLE_SEQNUM 8

//#define STATRACK_DEBUG

StationTracker::StationTracker()
    : _am_server(false), _node_id(0), _merged(false), _timer(this),
      _interval(15*60), _db(NULL), _log(NULL)
{
}

StationTracker::~StationTracker()
{
}

enum { H_ACTIVE_STATIONS, H_SEND_NOW };

void
StationTracker::add_handlers()
{
    if (!_am_server) {
        add_read_handler("active_stations", read_handler, (void*)H_ACTIVE_STATIONS);
        add_write_handler("send_now", write_handler, (void*)H_SEND_NOW);
    }
}

int
StationTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool has_node_id = false, has_merged = false;
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "NODE_ID", cpkC, &has_node_id, cpInteger, &_node_id,
            "MERGED", cpkC, &has_merged, cpBool, &_merged,
            "SERVER", 0, cpBool, &_am_server,
            "INTERVAL", 0, cpTimestamp, &_interval,
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

    if (_am_server) {
        if (has_node_id)
            return errh->error("NODE_ID parameter is meaningless when SERVER=true");

        if (has_merged)
            return errh->error("MERGED parameter is meaningless when SERVER=true");

        if (noutputs() != 0)
            return errh->error("when SERVER=true, element does not support outputs");
    }
    else {
        if (noutputs() == 0)
            return errh->error("when SERVER=false, element must have at least 1 output");

        // figure out our node ID if it wasn't given as a parameter
        if (!has_node_id) {
            char hostname[512];
            if (gethostname(hostname, sizeof(hostname)) != 0)
                return errh->error("gethostname: %s", strerror(errno));
            int *rv = NodeInfo::query_node_id(String(hostname));
            if (rv == NULL)
                return errh->error("no known node-id for host %s", hostname);
            _node_id = *rv;
        }
    }

    // check that elt is a pointer to a PostgreSQL element (if specified at all)
    if (elt != NULL) {
        _db = (PostgreSQL*)elt->cast("PostgreSQL");
        if (_db == NULL)
            return errh->error("DB element is not an instance of type PostgreSQL");
    }

    return 0;
}

int
StationTracker::initialize(ErrorHandler *)
{
    if (!_am_server) {
        _timer.initialize(this);
        _timer.schedule_after(_interval);
        _interval_start = Timestamp::now();
        _first_pkt = Timestamp(0);
        _last_pkt = Timestamp(0);
    }
    return 0;
}

void
StationTracker::push(int, Packet *p)
{
    if (_am_server) {
        const struct argos_stations_header *hdr =
            (const struct argos_stations_header*)p->data();

        if (p->length() < sizeof(struct argos_stations_header)) {
            _log->error("bad message received with length=%d and misc-ip=%s",
                p->length(), IPAddress(MISC_IP_ANNO(p)).unparse().c_str());
            p->kill();
            return;
        }

        if (ntohl(hdr->magic) != ARGOS_STATIONS_MSG_MAGIC) {
            _log->error("bad message received with magic=0x%08x and misc-ip=%s",
                ntohl(hdr->magic), IPAddress(MISC_IP_ANNO(p)).unparse().c_str());
            p->kill();
            return;
        }

        int32_t node_id = ntohl(hdr->node_id);
        bool is_merged = hdr->is_merged;
        uint32_t ts_sec = ntohl(hdr->ts_sec);
        uint32_t duration_sec = ntohl(hdr->duration_sec);
        uint32_t nrecords = ntohl(hdr->num_records);

        uint32_t reqlen = sizeof(struct argos_stations_header) +
            nrecords*sizeof(struct argos_stations_record);

        if (p->length() < reqlen) {
            _log->error("bad message received with nrecs=%u but len=%u (expected %u)",
                nrecords, p->length(), reqlen);
            p->kill();
            return;
        }

        if (p->length() > reqlen)
            _log->warning("oversized message received with nrecs=%u but len=%u (expected %u)",
                nrecords, p->length(), reqlen);

        const struct argos_stations_record *records = (const struct argos_stations_record*)
            (p->data() + sizeof(struct argos_stations_header));

        for (uint32_t i=0; i < nrecords; i++) {
            // insert data into database (if we have a db handle)
            EtherAddress station = EtherAddress(records[i].mac);
            if (_db) db_insert(node_id, is_merged, station, ts_sec, duration_sec,
                &(records[i]));

            _log->data("%llu packets reported by node %d (%s) for station %s",
                be64toh(records[i].packets), node_id, (is_merged ? "merged" : "raw"),
                station.unparse_colon().c_str());
        }

        // done!
        p->kill();
    } else {
        // !_am_server

        // although we can track the length of stats-gathering intervals using
        // wall-clock, its preferable to use packet timestamps so that this
        // element will work properly when reading from a dump (at faster than
        // the original capture rate)
        if (p->timestamp_anno() > _last_pkt) _last_pkt = p->timestamp_anno();
        if (_first_pkt.sec() == 0)
            _first_pkt = p->timestamp_anno();
        else
            if (p->timestamp_anno() < _first_pkt) _first_pkt = p->timestamp_anno();

        const u_char *ra = NULL, *ta = NULL;
        int rv = wifi_extract_addrs(p->data(), p->length(), NULL, &ta, NULL,
            &ra, NULL);

        // bad frame, or frame truncated, or no tx address
        if ((rv != 1) || (ra == NULL) || (ta == NULL)) {
            p->kill();
            return;
        };

        // these are transmitter/receiver, not (necessarily) the original
        // sender/destination
        EtherAddress dst = EtherAddress(ra);
        EtherAddress src = EtherAddress(ta);

        StationInfo *info = _stations.find(src);
        if (info == NULL) {
            info = new StationInfo();
            _stations.insert(src, info);
        }
        info->packets++;
        info->bytes += p->length();

        struct click_wifi *wifi = (struct click_wifi*)p->data();
        uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
        uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
        uint8_t dir = wifi->i_fc[1] & WIFI_FC1_DIR_MASK;
        uint8_t retry = wifi->i_fc[1] & WIFI_FC1_RETRY;

        // for all data and management frames, do sequence-number accounting
        if (type != WIFI_FC0_TYPE_CTL) {
            info->non_ctrl_packets++;

            if ((info->non_ctrl_packets == 1) && (info->first_iteration)) {
                if (info->last_seqnum != WIFI_SEQNUM_UNDEF)
                    _log->warn("XX-1  last_seqnum=%u", info->last_seqnum);
                if (info->last_seqnum_wqos != WIFI_SEQNUM_UNDEF)
                    _log->warn("XX-1  last_seqnum=%u", info->last_seqnum);
            }

            uint16_t seq = le16_to_cpu(*(uint16_t *) wifi->i_seq) >> WIFI_SEQ_SEQ_SHIFT;
            bool use_qos_counter = (type == WIFI_FC0_TYPE_DATA) &&
                (subtype & WIFI_FC0_SUBTYPE_QOS);
            
            // broadcast/multicast addresses do not use QoS seqnums
            if (ra[0] & 0x1)
                use_qos_counter = false;

            bool basic_counter_fallback = false;
            uint32_t base_seq_diff, qos_seq_diff, base_wqos_seq_diff;
            
            if (info->last_seqnum == WIFI_SEQNUM_UNDEF)
                // if the sequence number is "close to 0" then we guess that
                // this station just started sending 
                base_seq_diff = (seq < WIFI_LITTLE_SEQNUM) ? seq : 1;
            else
                base_seq_diff = WIFI_SEQNUM_DIFF(info->last_seqnum, seq, retry);

            // todo
            if ((info->non_ctrl_packets == 1) && (info->first_iteration)) {
                if (base_seq_diff > WIFI_LITTLE_SEQNUM) {
                    _log->warn("non_ctrl_pkts=%llu.  base_seq_diff=%u.  last_seqnum=%u.  seq=%u.  retry=%u.  first_iter=%d",
                        info->non_ctrl_packets, base_seq_diff, info->last_seqnum, seq, retry, info->first_iteration);
                }
            }

            if (info->last_seqnum_wqos == WIFI_SEQNUM_UNDEF)
                // if the sequence number is "close to 0" then we guess that
                // this station just started sending 
                base_wqos_seq_diff = (seq < WIFI_LITTLE_SEQNUM) ? seq : 1;
            else
                base_wqos_seq_diff = WIFI_SEQNUM_DIFF(info->last_seqnum_wqos,
                    seq, retry);

            // todo
            if ((info->non_ctrl_packets == 1) && (info->first_iteration)) {
                if (base_seq_diff > WIFI_LITTLE_SEQNUM) {
                    _log->warn("non_ctrl_pkts=%llu.  base_wqos_seq_diff=%u.  last_seqnum_wqos=%u.  seq=%u.  retry=%u, first_iter=%d",
                        info->non_ctrl_packets, base_wqos_seq_diff, info->last_seqnum_wqos, seq, retry, info->first_iteration);
                }
            }

            if (use_qos_counter) {
                // TID is stored in the low 3 bits of the QoS control field
                struct ieee80211_qosframe *qosframe = (struct ieee80211_qosframe *)wifi;
                uint8_t tid = (qosframe->i_qos[0]) & 0xF;
                assert(tid < 16);

                QoSCounter *qoscnt = info->_qos_counters.findp(dst);
                if (qoscnt == NULL) {
                    QoSCounter qc;
                    (void) info->_qos_counters.insert(dst, qc);
                    qoscnt = info->_qos_counters.findp(dst);
                    assert(qoscnt != NULL);
                }

                // according to the 802.11 spec, the sequence numbers of null
                // data frames may be set to any value (which to me implies that
                // they do not advance the counter, but I don't see this
                // explicitly), but I don't trust everyone to implement this, so
                // we don't count null frames, but we do keep track of what the
                // current counter state would be if it advances for null frames
                if ((subtype & WIFI_FC0_SUBTYPE_QOS_NULL) == WIFI_FC0_SUBTYPE_QOS_NULL) {
                    qoscnt->last_seqnum_wnulls[tid] = seq;
                    info->inferred_packets++;
#ifdef STATRACK_DEBUG
                    click_chatter("%s: QoS null data frame (no updates)",
                        p->timestamp_anno().unparse().c_str());
#endif
                } else {
                    if (qoscnt->last_seqnum[tid] == WIFI_SEQNUM_UNDEF) {
                        // if the sequence number is "close to 0" then we guess
                        // that this station just began sending (starting from
                        // seqnum 0) and we missed the first few frames
                        qos_seq_diff = (seq < WIFI_LITTLE_SEQNUM) ? seq : 1;
                    } else {
                        qos_seq_diff = WIFI_SEQNUM_DIFF(qoscnt->last_seqnum[tid],
                            seq, retry);

                        // also check what the diff would be if QoS-NULL frames
                        // (erroneously) consumed seqnums
                        uint32_t diff_alt = WIFI_SEQNUM_DIFF(qoscnt->last_seqnum_wnulls[tid],
                            seq, retry);

                        if (diff_alt < qos_seq_diff)
                            qos_seq_diff = diff_alt;
                    }

                    if ((qoscnt->last_qos_tid != WIFI_QOS_TID_UNDEF) && (qoscnt->last_qos_tid != tid)) {
                        // it appears that some stations reset the QoS seqnum
                        // counter to 0 whenever they change from one TID to
                        // another, so if the TID changes then check if the new
                        // seqnum is near 0 which may imply this happened
                        uint32_t diff_alt = seq + 1;

                        if ((seq < WIFI_LITTLE_SEQNUM) && (diff_alt < qos_seq_diff)) {
#ifdef STATRACK_DEBUG
                            click_chatter("%s:   %s reset seqnums for TID change (diff=%u, diff_alt=%u, seq=%u)",
                                p->timestamp_anno().unparse().c_str(),
                                src.unparse_colon().c_str(), qos_seq_diff, diff_alt, seq);
#endif
                            qos_seq_diff = diff_alt;
                        }
                    }

                    // go ahead and update the QoS counters for this TID...
                    qoscnt->last_seqnum[tid] = seq;
                    qoscnt->last_seqnum_wnulls[tid] = seq;
                    qoscnt->last_qos_tid = tid;

                    // and then one more check for weird behavior (whether the
                    // station is using its base seqnum counter instead of the
                    // appropriate qos seqnum counter)
                    if (info->qos_ignored_votes <= -0x10) {
                        // nevermind - we've already decided that we don't think
                        // this station has this problem
                    }
                    else if (info->qos_ignored_votes >= 0x100) {
                        // we've already decided that we DO think that this
                        // station has this problem
                        basic_counter_fallback = true;
                    } else {
                        // we haven't made up our mind yet

                        // if the 'error' for using the QoS counter is small,
                        // then assume that's the right thing to do
                        if (qos_seq_diff < WIFI_LITTLE_SEQNUM) {
                            if (base_wqos_seq_diff >= WIFI_LITTLE_SEQNUM) {
                                // QoS counter estimate is good, base counter
                                // estimate is bad --> I vote that this station
                                // does NOT have the ignore-qos problem!
                                info->qos_ignored_votes--;

#ifdef STATRACK_DEBUG
                                click_chatter("%s:   QoS bug NO VOTE for %s (votes=%d)  base=%u qos=%u",
                                    p->timestamp_anno().unparse().c_str(),
                                    src.unparse_colon().c_str(), info->qos_ignored_votes,
                                    base_wqos_seq_diff, qos_seq_diff);
#endif
                            }
                        }
                        else {
                            // else, the QoS counter estimate is bad...

                            if (base_wqos_seq_diff < WIFI_LITTLE_SEQNUM) {
                                // and the base counter estimate is good!
                                basic_counter_fallback = true;

                                // I vote that this station DOES have the
                                // ignore-qos problem!
                                info->qos_ignored_votes++;

#ifdef STATRACK_DEBUG
                                click_chatter("%s:   QoS bug YES VOTE for %s  (votes=%d)  base=%u qos=%u",
                                    p->timestamp_anno().unparse().c_str(),
                                    src.unparse_colon().c_str(), info->qos_ignored_votes,
                                    base_wqos_seq_diff, qos_seq_diff);
#endif
                            }
                            // else, the base counter estimate is also bad;
                            // looks like one way or another we missed a bunch
                            // of packets and we have no way to guess which is
                            // right so just assume that we should use the qos
                            // counter
                        }
                    }

                    // assuming we aren't supposed to fall back to the basic
                    // counter, finally ok to update our packet estimate
                    if (!basic_counter_fallback) {
                        if (qos_seq_diff > 0) {
                            // sanity check; the seqnum field is only 12 bits,
                            // so qos_seq_diff should never exceed 4096
                            assert(qos_seq_diff <= 4096);
                            info->inferred_packets += qos_seq_diff;
                        } else {
                            // else, probably an 802.11 retransmission
                            info->inferred_packets++;  // perhaps a frame resend
                        }
#ifdef STATRACK_DEBUG
                        click_chatter("%s: %s tid %d for %s updated by %u to %u"
                            "  (diff-from-base=%u)", p->timestamp_anno().unparse().c_str(),
                            src.unparse_colon().c_str(), tid, dst.unparse_colon().c_str(),
                            qos_seq_diff, seq, base_wqos_seq_diff);
#endif
                    }
                }
            }

            if (!use_qos_counter || basic_counter_fallback) {
                uint32_t diff;
                if (basic_counter_fallback) {
                    // sanity check; the seqnum field is only 12 bits,
                    // so base_wqos_seq_diff should never exceed 4096
                    assert(base_wqos_seq_diff <= 4096);
                    diff = base_wqos_seq_diff;
#ifdef STATRACK_DEBUG
                    click_chatter("%s: %s base counter updated by %u to %u (dst=%s"
                        ", diff-from-qos=%u)", p->timestamp_anno().unparse().c_str(),
                        src.unparse_colon().c_str(), base_wqos_seq_diff, seq,
                        dst.unparse_colon().c_str(), qos_seq_diff);
#endif
                } else {
                    // sanity check; the seqnum field is only 12 bits,
                    // so base_seq_diff should never exceed 4096
                    assert(base_seq_diff <= 4096);
                    diff = base_seq_diff;
#ifdef STATRACK_DEBUG
                    click_chatter("%s: %s base counter updated by %u to %u (dst=%s)",
                        p->timestamp_anno().unparse().c_str(),
                        src.unparse_colon().c_str(), base_seq_diff, seq,
                        dst.unparse_colon().c_str());
#endif
                }

                info->last_seqnum = seq;
                if (diff > 0)
                    info->inferred_packets += diff;
                else
                    info->inferred_packets++;  // perhaps a frame resend
            }

            // always update last_seqnum_wqos, for both QoS and non-QoS frames
            info->last_seqnum_wqos = seq;
        }

        // ignore null data frames when compiling data-type stats
        if ((type == WIFI_FC0_TYPE_DATA) && ((subtype & WIFI_FC0_SUBTYPE_NODATA) == 0)) {
            info->data_bytes += p->length();
                
            if (wifi->i_fc[1] & WIFI_FC1_WEP) {
                info->encr_data_bytes += p->length();
            } else {
                size_t hdrlen = wifi_header_len(p->data());

                struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
                if ((ceh->magic == WIFI_EXTRA_MAGIC) && (ceh->flags & WIFI_EXTRA_DATAPAD) && (hdrlen & 3))
                    hdrlen += 4 - (hdrlen & 3);

                if (p->length() > (hdrlen + WIFI_LLC_HEADER_LEN)) {
                    const u_char *llc = p->data() + hdrlen;
                    if (memcmp(WIFI_LLC_HEADER, llc, WIFI_LLC_HEADER_LEN) == 0)
                        info->layer3_bytes += p->length() - hdrlen - WIFI_LLC_HEADER_LEN;
                }
            }

            if (dir == WIFI_FC1_DIR_NODS)
                info->is_ibss = true;

            if (dir == WIFI_FC1_DIR_FROMDS)
                info->is_ap = true;

            if (dir == WIFI_FC1_DIR_TODS)
                info->is_client = true;
        }

        if ((type == WIFI_FC0_TYPE_MGT) && (subtype == WIFI_FC0_SUBTYPE_BEACON)) {
            info->beacons++;

            // anyone who sends Beacons must be an AP
            info->is_ap = true;

            // and might be an IBSS station
            int capinfo;
            if (wifi_parse_capinfo(p->data(), p->length(), &capinfo)) {
                if (capinfo & WIFI_CAPINFO_IBSS)
                    info->is_ibss = true;
            }

            // also parse out the beacon interval field
            int bcn_int;
            if (wifi_parse_bcnint(p->data(), p->length(), &bcn_int)) {
                if (info->bcn_int > 0) {
                    // we have already seen a beacon interval from this station;
                    // just confirm that they are the same
                    if (bcn_int != info->bcn_int) {
                        // beacon intervals differ; mark interval as 'invalid'
                        info->bcn_int = -1;
                    }
                } else {
                    // this is the first beacon interval seen from this station;
                    // just record it
                    info->bcn_int = bcn_int;
                }
            }
        }

        p->kill();
    }
}

void
StationTracker::run_timer(Timer *)
{
    Timestamp now = Timestamp::now();
    Timestamp started = _interval_start;
    Timestamp elapsed = now - _interval_start;
    Timestamp pkt_elapsed = _last_pkt - _first_pkt;
    _timer.reschedule_after(_interval);
    _interval_start = now;
    _first_pkt = Timestamp(0);
    _last_pkt = Timestamp(0);

    // if pkt_elapsed is less than [wall-clock] elapsed, then use wall-clock
    // because it probably means that we were doing a live capture (and if the
    // packet frequency is very low, pkt_elapsed could be really wrong),
    // otherwise use pkt_elapsed as it probably means we were reading from a
    // dumpfile (or we were doing a live capture and the two values are nearly
    // equal in which case it doesn't matter which we choose)
    if (pkt_elapsed > elapsed) elapsed = pkt_elapsed;

    uint32_t ndeleted = 0;

    // first go through and discard all stations from which we received nothing
    HashMap<EtherAddress, StationInfo*>::iterator iter = _stations.begin();
    for (; iter != _stations.end(); iter++) {
        if (iter.value()->packets == 0) {
            StationInfo *ptr = iter.value();
            bool deleted = _stations.erase(iter.key());
            assert(deleted);
            ndeleted++;
            delete ptr;
        }
    }

    _log->debug("deleted %u expired station entires", ndeleted);

    // now we know how big of a packet we will need
    size_t nrecords = _stations.size();
    size_t reqlen = sizeof(struct argos_stations_header) +
        nrecords*sizeof(struct argos_stations_record);

    WritablePacket *p;
    try {
        p = Packet::make(0, NULL, reqlen, 0);
    }
    catch (std::bad_alloc &ex) {
        _log->error("Packet::make failed for len %u", reqlen);
        return;
    }

    _log->debug("allocated %u byte packet", reqlen);
    struct argos_stations_header *hdr = (struct argos_stations_header*)p->data();
    hdr->magic = htonl(ARGOS_STATIONS_MSG_MAGIC);
    hdr->node_id = htonl(_node_id);
    hdr->is_merged = (_merged ? 1 : 0);
    hdr->ts_sec = htonl(started.sec());
    hdr->duration_sec = htonl(elapsed.sec());
    hdr->num_records = htonl(nrecords);
    
    struct argos_stations_record *records = (struct argos_stations_record*)
        (p->data() + sizeof(struct argos_stations_header));

    uint32_t i = 0;
    for (iter = _stations.begin(); iter != _stations.end(); iter++) {
        if (i >= nrecords) {
            _log->critical("index failure.  i=%u, nrecords=%u, hashlen=%u",
                i, nrecords, _stations.size());
            p->kill();
            return;
        }

        // calculate from the beacon interval and the elapsed time how many
        // beacons should have been sent
        uint64_t inferred_beacons = 0;
        if (iter.value()->bcn_int > 0) {
            // beacon intervals are in units of 1024 microseconds - note that
            // due to integer division this might be a bit inaccurate for very
            // short elapsed times, but even with floating point we will be
            // inaccurate over short time intervals since we are estimating
            // discrete phenomena
            inferred_beacons = (1000*(uint64_t)elapsed.msecval())/(1024*iter.value()->bcn_int);
        }

        uint16_t flags = 0;
        if (iter.value()->is_ibss) flags += ARGOS_STATIONS_F_IBSS;
        if (iter.value()->is_ap) flags += ARGOS_STATIONS_F_AP;
        if (iter.value()->is_client) flags += ARGOS_STATIONS_F_CLIENT;

        memcpy(records[i].mac, iter.key().data(), 6);
        records[i].packets = htobe64(iter.value()->packets);
        records[i].bytes = htobe64(iter.value()->bytes);
        records[i].non_ctrl_packets = htobe64(iter.value()->non_ctrl_packets);
        records[i].inferred_packets = htobe64(iter.value()->inferred_packets);
        records[i].data_bytes = htobe64(iter.value()->data_bytes);
        records[i].encrypt_data_bytes = htobe64(iter.value()->encr_data_bytes);
        records[i].layer3_bytes = htobe64(iter.value()->layer3_bytes);
        records[i].flags = htons(flags);
        records[i].beacons = htobe64(iter.value()->beacons);
        records[i].inferred_beacons = htobe64(inferred_beacons);
        i++;

        // reset all stats counters to 0
        iter.value()->clear_stats();
    }

    if (i != nrecords) {
        _log->critical("index failure.  i=%d, nrecords=%u, hashlen=%u",
            i, nrecords, _stations.size());
        p->kill();
        return;
    }

    output(0).push(p);
}

void
StationTracker::db_insert(int32_t node_id, bool merged, const EtherAddress &src,
    uint32_t ts_sec, uint32_t duration_sec,
    const struct argos_stations_record *record)
{
    Vector<const char*> values;

    static const String raw_query = String("INSERT INTO station_stats"
        " (capt_node_id, mac, timestamp, duration_sec, packets, bytes"
        ", non_ctrl_packets, inferred_packets, data_bytes, encrypt_data_bytes"
        ", layer3_bytes, flags, beacons, inferred_beacons)"
        " VALUES ($1, $2, timestamptz 'epoch' + $3 * interval '1 second'"
        ", $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);");

    static const String agg_query = String("INSERT INTO station_stats"
        " (agg_node_id, mac, timestamp, duration_sec, packets, bytes"
        ", non_ctrl_packets, inferred_packets, data_bytes, encrypt_data_bytes"
        ", layer3_bytes, flags, beacons, inferred_beacons)"
        " VALUES ($1, $2, timestamptz 'epoch' + $3 * interval '1 second'"
        ", $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);");

    String node_id_str = String(node_id);
    String src_str = src.unparse();
    String ts_sec_str = String(ts_sec);
    String duration_str = String(duration_sec);
    String packets = String(be64toh(record->packets));
    String bytes = String(be64toh(record->bytes));
    String non_ctrl_packets = String(be64toh(record->non_ctrl_packets));
    String inferred_packets = String(be64toh(record->inferred_packets));
    String data_bytes = String(be64toh(record->data_bytes));
    String encrypt_data_bytes = String(be64toh(record->encrypt_data_bytes));
    String layer3_bytes = String(be64toh(record->layer3_bytes));
    String flags = String((uint32_t)ntohs(record->flags));
    String beacons = String(be64toh(record->beacons));
    String inferred_beacons = String(be64toh(record->inferred_beacons));

    values.push_back(node_id_str.c_str());
    values.push_back(src_str.c_str());
    values.push_back(ts_sec_str.c_str());
    values.push_back(duration_str.c_str());
    values.push_back(packets.c_str());
    values.push_back(bytes.c_str());
    values.push_back(non_ctrl_packets.c_str());
    values.push_back(inferred_packets.c_str());
    values.push_back(data_bytes.c_str());
    values.push_back(encrypt_data_bytes.c_str());
    values.push_back(layer3_bytes.c_str());
    values.push_back(flags.c_str());
    values.push_back(beacons.c_str());
    values.push_back(inferred_beacons.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv;
    if (merged)
        rv = _db->db_execute(agg_query, values, &errh);
    else
        rv = _db->db_execute(raw_query, values, &errh);

    if (rv < 0) {
        StringAccum sa;
        for (int i=0; i < values.size(); i++)
            sa << String(values[i]) << " | ";
        _log->error("db_insert failed: %s  (args: %s)",
            errh.get_last_error().c_str(), sa.take_string().c_str());
    }
    else if (rv == 1)
        _log->debug("1 row inserted for BSSID %s, node_id %d", src_str.c_str(),
            node_id);
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for BSSID %s, node_id %d", rv,
            src_str.c_str(), node_id);
}

/*
 * STATIC METHODS
 */

String
StationTracker::read_handler(Element *e, void *thunk)
{
    const StationTracker *elt = static_cast<StationTracker *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_ACTIVE_STATIONS:
        return String(elt->_stations.size());
    default:
        return "internal error (bad thunk value)";
    }
}

int
StationTracker::write_handler(const String&, Element *e, void *thunk,
    ErrorHandler *errh)
{
    StationTracker *elt = static_cast<StationTracker *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_SEND_NOW:
        elt->_timer.schedule_now();
        return 0;
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(StationTracker)
