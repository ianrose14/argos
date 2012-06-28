/*
 * wifimerge.{cc,hh} -- merge 802.11 frames from multiple sources.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifimerge.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include "../wifiutil.hh"
#include "../argos/anno.h"

CLICK_DECLS

#define WIFIMERGE_INIT_HEAPSIZE 1024
#define WIFIMERGE_TIMER_INTERVAL_MS 50

// custom HEAP_COMPARE definition to compare WifiMergeRecord pointers in _sendq
#undef HEAP_COMPARE
#define HEAP_COMPARE(a, b) ((a)->scheduled_output() <= (b)->scheduled_output() ? -1 : 1)

#ifndef min
#define min(a, b) (a <= b ? a : b)
#endif

// todo
int32_t WifiMerge::_net_allocs = 0;
uint32_t WifiMerge::_allocs = 0;
#define FOCUS()                                 \
    do {                                        \
        assert(_allocs == 0);                   \
        _allocs = Packet::packet_allocs();      \
    } while (0)
#define UNFOCUS()                                               \
    do {                                                        \
        _net_allocs += (Packet::packet_allocs() - _allocs);     \
        _allocs = 0;                                            \
    } while (0)

/*
 * Static methods
 */

static Timestamp
average_timestamps(Timestamp &a, Timestamp &b)
{
    // a bit annoying to find the average of two Timestamps without running into
    // overflow problems
    int32_t min_sec = a.sec() < b.sec() ? a.sec() : b.sec();
    uint32_t min_subsec = a.subsec() < b.subsec() ? a.subsec() : b.subsec();

    // properly handles the case when a.subsec() and b.subsec() are both odd,
    // which (a.subsec()/2 + b.subsec()/2) does not
    uint32_t subsec = min_subsec + (a.subsec() - min_subsec)/2 +
        (b.subsec() - min_subsec)/2;

    int32_t sec_add= (a.sec() - min_sec) + (b.sec() - min_sec);
    int32_t sec = sec_add/2 + min_sec;

    // if (a.sec() + b.sec() is odd, handle the fraction leftover (0.5s)
    if ((sec_add & 1) == 1) {
        // make sure subsec field does not overflow
        if (subsec >= Timestamp::subsec_per_sec/2) {
            sec += 1;
            subsec -= Timestamp::subsec_per_sec/2;
        } else {
            subsec += Timestamp::subsec_per_sec/2;
        }
    }

    return Timestamp(sec, subsec);
}

/*
 * WifiMergeRecord methods
 */

WifiMergeRecord::WifiMergeRecord(uint32_t hash, Timestamp output_timeout)
    : _output_timeout(output_timeout), _hash(hash), _prev_upper_bound(0, 0)
{
}

WifiMergeRecord::~WifiMergeRecord()
{
    PacketList::iterator iter = _pkt_list.begin();
    while (iter != _pkt_list.end()) {
	PacketListNode *node = iter.get();
        node->p->kill();
	iter = _pkt_list.erase(iter);
	delete node;
    }
}

bool
WifiMergeRecord::add_packet(Packet *p)
{
    if (p->timestamp_anno() <= _prev_upper_bound)
        return false;  // fail - this packet should be treated as a dupe    

    // record when this packet was received; we don't use the packet timestamp
    // because we want to be insensitive to processing delays
    // (e.g. TimestampSort elements) prior to receiving the packet    
    PacketListNode *node = new PacketListNode(p);
    if (node == NULL)
        return false;

    node->received = Timestamp::now();

    // insert packet into list in packet-timestamp-sorted order
    PacketList::iterator iter = _pkt_list.begin();
    for (; iter != _pkt_list.end(); iter++) {
        Packet *q = iter.get()->p;
        if (p->timestamp_anno() <= q->timestamp_anno()) {
            _pkt_list.insert(iter, node);
            return true;
        }
    }

    _pkt_list.push_back(node);
    return true;
}

Packet *
WifiMergeRecord::make_dupe_packet(Packet *p)
{
    size_t reqlen = sizeof(struct argos_wifimerge) +
        1*sizeof(struct argos_wifimerge_elt);

    WritablePacket *q = p->push(reqlen);
    if (q == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    struct argos_wifimerge *hdr = (struct argos_wifimerge*)q->data();
    memset(hdr, '\0', sizeof(struct argos_wifimerge));
    hdr->magic = ARGOS_WIFIMERGE_MAGIC;
    hdr->num_elts = 1;
    hdr->flags = ARGOS_WIFIMERGE_ISDUPE;

    struct argos_wifimerge_elt *elts = (struct argos_wifimerge_elt*)
        (q->data() + sizeof(struct argos_wifimerge));

    uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;
    click_wifi_extra *wifi_ex = WIFI_EXTRA_ANNO(p);

    elts[0].src = sniff->sniffer;
    elts[0].ts = p->timestamp_anno().timeval();
    elts[0].channel = sniff->channel;
    elts[0].rssi = wifi_ex->rssi;
    elts[0].noise = wifi_ex->silence;

    // save the wifimerge header's offset (relative to the mac header) in the
    // packet's annotations
    if (q->has_mac_header()) {
        assert(q->mac_header() > q->data());
        SET_WIFIMERGE_ANNO(q, q->mac_header() - q->data());
    }

    return q;
}

Packet *
WifiMergeRecord::make_merged_packet(uint32_t *merged_count, uint32_t *merged_mem)
{
    // since _pkt_list is sorted by timestamp (ascending), the head of the list
    // (base_pkt) has the earliest timestamp and is the packet that we will be
    // outputting (after searching through the list and pulling out whichever
    // entries we think are copies of base_pkt).
    assert(_pkt_list.size() > 0);
    assert(_pkt_list.front() != NULL);
    Packet *base_pkt = _pkt_list.front()->p;
    assert(base_pkt->length() >= 10);

    struct click_wifi *wifi = (struct click_wifi*)base_pkt->data();
    Timestamp skew_err = Timestamp::make_usec(0, TIMESKEW_ERR_ANNO(base_pkt));

    if (wifi->i_fc[0] & WIFI_FC0_TYPE_CTL) {
        // control frames have a much higher chance of collisions (i.e. 2
        // distinct frames being sent with the exact same bits) within a short
        // time frame, so we use an especially small window of time to merge
        // over (this means that
        static Timestamp ctrl_skew_max = Timestamp::make_usec(0, MAX_TIMESKEW_ERR_CTRL);
        if (skew_err > ctrl_skew_max)
            skew_err = ctrl_skew_max;
    } else {
        static Timestamp skew_max = Timestamp::make_usec(0, MAX_TIMESKEW_ERR);
        if (skew_err < skew_max)
            skew_err = skew_max;
    }

    // any packet with [timestamp - timeskew-err] less than or equal to this
    // value will be merged with the base packet
    Timestamp merge_hi_bound = base_pkt->timestamp_anno() + skew_err;

    // any packet with a timestamp greater than this value, regardless of its
    // timeskew error, will not be merged with the base packet (because packets'
    // timeskew errors are capped)
    Timestamp ts_limit = merge_hi_bound + Timestamp::make_usec(0, MAX_TIMESKEW_ERR);

    uint8_t *base_anno_ptr = base_pkt->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    const struct argos_sniff *base_sniff = (struct argos_sniff *)base_anno_ptr;

    // first, scan through the list looking for any packets from the same
    // sniffer as the base packet, but with a different timestamp.  If so, these
    // MUST be records of a different frame (even if the same frame is captured
    // on multiple different pcap descriptors on a node, they will all have the
    // same timestamp because its the network interface that records the
    // timestamp).
    PacketList::iterator iter = _pkt_list.begin();
    for (; iter != _pkt_list.end(); iter++) {
        Packet *p = iter.get()->p;

        uint8_t *iter_anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
        const struct argos_sniff *iter_sniff = (struct argos_sniff *)iter_anno_ptr;

        if ((base_sniff->sniffer == iter_sniff->sniffer) &&
            (base_pkt->timestamp_anno() != p->timestamp_anno())) {
            // we just cut the time difference between base_pkt and this packet
            // in half; any packets captured with a timestamp closer to base_pkt
            // are merged in, and any packets captured with a timestamp closer
            // to this packet are not merged (i.e. are left in the list)
            Timestamp halfway = average_timestamps(base_pkt->timestamp_anno(),
                p->timestamp_anno());
            if (halfway < ts_limit)
                ts_limit = halfway;
            break;
        }
    }

    // iterate through the list again (now that ts_limit is definitely set
    // properly) pulling out packets that should be merged with the base packet
    Vector<struct argos_wifimerge_elt> members;
    uint8_t best_channel = 0;
    struct in_addr best_src = IPAddress("1.2.3.4").in_addr();
    int best_rssi = -999;

    if (merged_mem != NULL) *merged_mem = 0;

    iter = _pkt_list.begin();
    while (iter != _pkt_list.end()) {
        PacketListNode *node = iter.get();
        Packet *p = node->p;

        if (p->timestamp_anno() > ts_limit) {
            // this packet was captured so far after the base packet that,
            // regardless of what its timeskew error is, it has no chance of
            // being merged with the base packet; assuming that packets are
            // received in time-sorted order, this means that this is also true
            // for all subsequent packets
            break;
        }

        Timestamp skew_err = Timestamp::make_usec(0, TIMESKEW_ERR_ANNO(p));
        Timestamp low_ts = p->timestamp_anno() - skew_err;

        if (low_ts > merge_hi_bound) {
            // this packet's timeskew-error is tight enough that we don't think
            // it should be merged with the base packet, but we need to keep
            // searching because later packets (even though we expect them to
            // have later timestamps) might have much larger timeskew errors
            // that will allow them to merge
            iter++;
            continue;
        }

        uint8_t *iter_anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
        const struct argos_sniff *iter_sniff = (struct argos_sniff *)iter_anno_ptr;

        bool sniffer_already_in_list = false;
        for (int i=0; i < members.size(); i++) {
            if (iter_sniff->sniffer == members[i].src) {
                // a packet from this same sniffer has already been merged in;
                // since there (normally) can't be two copies of the same packet
                // captured by the same sniffer, we do not allow merging in of
                // more than one packet for each sniffer
                sniffer_already_in_list = true;
                break;
            }
        }

        if (sniffer_already_in_list) {
            iter++;
            continue;
        }

        // otherwise, merge this packet with the base packet
 
        click_wifi_extra *wifi_ex = WIFI_EXTRA_ANNO(p);
        struct argos_wifimerge_elt elt;
        elt.src = iter_sniff->sniffer;
        elt.ts = FIRST_TIMESTAMP_ANNO(p).timeval();
        elt.channel = iter_sniff->channel;
        elt.rssi = wifi_ex->rssi;
        elt.noise = wifi_ex->silence;
        elt.unused_space[0] = 0;  // to make the compiler happy
 
        members.push_back(elt);

        int rssi = elt.rssi - elt.noise;
        if (rssi > (best_rssi + WIFIMERGE_RSSI_THRESH)) {
            // this RSSI is significantly better than the previous best, so
            // this channel becomes our estimate for the "real" channel and
            // this sniffer becomes the "representative" sniffer
            best_rssi = rssi;
            best_channel = elt.channel;
            best_src = elt.src;
        } else if (rssi > (best_rssi - WIFIMERGE_RSSI_THRESH)) {
            // this RSSI is close enough to the previous best that we may have a
            // conflict if our current and previous channel estimates differ (in
            // which case we punt on guessing at the "real" channel)
            if (elt.channel != best_channel)
                best_channel = 0;
        }

        if (merged_mem != NULL) *merged_mem += p->length() + sizeof(Packet);

        // base_pkt is not killed because it will be used to make (via
        // Packet::push) the output packet
        if (p != base_pkt)
            p->kill();
 
        iter = _pkt_list.erase(iter);
        delete node;
    }

    assert(members.size() > 0);
    if (merged_count != NULL) *merged_count = members.size();

    size_t reqlen = sizeof(struct argos_wifimerge) +
        members.size()*sizeof(struct argos_wifimerge_elt);

    WritablePacket *q = base_pkt->push(reqlen);
    if (q == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    // set appropriate argos and wifi-extra annotations on output packet
    // (although a number of fields are meaningless in merged packets, such as
    // argos_sniff.sender and click_wifi_extra.rssi
    uint8_t *anno_ptr = q->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;
    sniff->channel = best_channel;
    sniff->sniffer = best_src;

    struct argos_wifimerge *hdr = (struct argos_wifimerge*)q->data();
    memset(hdr, '\0', sizeof(struct argos_wifimerge));
    hdr->magic = ARGOS_WIFIMERGE_MAGIC;
    hdr->num_elts = members.size();

    struct argos_wifimerge_elt *elts = (struct argos_wifimerge_elt*)
        (q->data() + sizeof(struct argos_wifimerge));

    for (int i=0; i < members.size(); i++)
        memcpy(&elts[i], &members[i], sizeof(struct argos_wifimerge_elt));

    // we want to set the timestamp to the median value of all merged
    // timestamps; if the number of elements is even, we arbitrarily pick one of
    // the two middle values
    if (members.size() > 1)
        q->set_timestamp_anno(elts[members.size()/2].ts);

    // save the wifimerge header's offset (relative to the mac header) in the
    // packet's annotations
    if (q->has_mac_header()) {
        assert(q->mac_header() > q->data());
        SET_WIFIMERGE_ANNO(q, q->mac_header() - q->data());
    }

    _last_pkt_output = Timestamp::now();
    _prev_upper_bound = ts_limit;
    return q;
}

uint32_t
WifiMergeRecord::packet_count() const
{
    uint32_t c = 0;
    PacketList::const_iterator iter = _pkt_list.begin();
    for (; iter != _pkt_list.end(); iter++)
        c++;
    return c;
}

/*
 * WifiMerge methods
 */

WifiMerge::WifiMerge()
    : _task(this), _timer(this), _sendq(NULL), _output_timeout(10), _expire_timeout(120),
      _mem_high_thresh(1024*1024), _mem_usage(0), _mem_warning(false),
      _stored_packets(0), _early_merges(0), _merge_in_count(0), _merge_out_count(0),
      _log(NULL)
{
    assert(sizeof(struct click_wifi_extra) == WIFI_EXTRA_ANNO_SIZE);
}

WifiMerge::~WifiMerge()
{
    while (1) {
        HashMap<uint32_t, WifiMergeRecord*>::iterator iter = _record_map.begin();
        if (iter == _record_map.end()) break;
        WifiMergeRecord *record = iter.value();
        _record_map.remove(iter.key());
        delete record;
    }

    if (_sendq != NULL) HEAP_DESTROY(_sendq);
    if (_log != NULL) delete _log;
}

enum { H_RECORD_COUNT, H_SEND_LEN, H_EXPIRE_LEN,
       H_AVG_MERGE, H_RESET,
       H_COUNTS, H_EXP_PACKET_COUNT, H_MIN_PACKET };

void
WifiMerge::add_handlers()
{
    add_data_handlers("packet_count", Handler::OP_READ, &_stored_packets);
    add_read_handler("record_count", read_handler, (void*)H_RECORD_COUNT);
    add_data_handlers("early_merges", Handler::OP_READ, &_early_merges);
    add_read_handler("send_len", read_handler, (void*)H_SEND_LEN);
    add_read_handler("expire_len", read_handler, (void*)H_EXPIRE_LEN);
    add_read_handler("avg_merge", read_handler, (void*)H_AVG_MERGE);
    add_data_handlers("mem_usage", Handler::OP_READ, &_mem_usage);
    add_write_handler("reset", write_handler, (void*)H_RESET);

    // todo
    add_read_handler("allocs", read_handler, (void*)H_COUNTS);
    add_read_handler("exp_packet_count", read_handler, (void*)H_EXP_PACKET_COUNT);
    add_read_handler("min_packet", read_handler, (void*)H_MIN_PACKET);
}

int
WifiMerge::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "TIMEOUT", cpkP, cpTimestamp, &_output_timeout,
            "EXPIRY", cpkP, cpTimestamp, &_expire_timeout,
            "HIMEM", 0, cpUnsigned, &_mem_high_thresh,
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

    return 0;
}

int
WifiMerge::initialize(ErrorHandler *errh)
{
    HEAP_CREATE(WIFIMERGE_INIT_HEAPSIZE, sizeof(WifiMergeRecord *), _sendq);

    ScheduleInfo::initialize_task(this, &_task, false, errh);

    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

void
WifiMerge::push(int, Packet *p)
{
    FOCUS();

    // verify that input packet has an Argos annotation
    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    const struct argos_sniff *sniff = (const struct argos_sniff *)anno_ptr;

    if (sniff->magic != ARGOS_SNIFF_MAGIC) {
        _log->error("missing or bad Argos sniff annotation in received packet");
        p->kill();
        // todo
        UNFOCUS();
        return;
    }

    uint32_t hash = hash_packet(p);
    WifiMergeRecord *record = _record_map.find(hash);
    bool is_expiring = false;
    bool needs_send_enqueue = false;

    if (record == NULL) {
        _log->debug("packet recv'd w/ hash=0x%08x and ts=%s (no existing record)",
            hash, p->timestamp_anno().unparse().c_str());
        record = new WifiMergeRecord(hash, _output_timeout);
        needs_send_enqueue = true;
        _record_map.insert(hash, record);
    } else {
        if (record->is_empty()) {
            // whenever a record is empty, that means that its currently
            // scheduled for expiration
            is_expiring = true;
            needs_send_enqueue = true;
            Timestamp expiry = record->expiration_time();
            Timestamp left = Timestamp::now() - expiry;

            _log->debug("packet recv'd w/ hash=0x%08x and ts=%s (empty record"
                " exists; expiration in %d ms)", hash,
                p->timestamp_anno().unparse().c_str(), left.msecval());
        } else {
            // non-empty record; must be scheduled for output
            Timestamp expiry = record->scheduled_output();
            Timestamp left = expiry - Timestamp::now();

            _log->debug("packet recv'd w/ hash=0x%08x and ts=%s (non-empty record"
                " exists; timeout in %s)", hash,
                p->timestamp_anno().unparse().c_str(), left.unparse().c_str());
        }
    }

    // record the packet contents (if we don't have it already from a previous
    // copy), this sniffer's RSSI/noise, and then dispose of the packet if its
    // not needed
    if (record->add_packet(p)) {
        _stored_packets++;

        // update running memory total (we use a worst-case memory accounting
        // which assumes that no packets are shared)
        _mem_usage += p->length() + sizeof(Packet);

        // enqueue this record onto the send queue, if needed (i.e. its not
        // already enqueued)
        if (needs_send_enqueue)
            HEAP_ADD(_sendq, WifiMergeRecord*, record);

        while (_mem_usage > _mem_high_thresh) {
            if (!_mem_warning) {
                _log->warning("sending merged packets early to shed memory (usage of %u > thresh of %u)",
                    _mem_usage, _mem_high_thresh);
                _mem_warning = true;
            }

            if (HEAP_COUNT(_sendq) > 0) {
                WifiMergeRecord *record = NULL;
                HEAP_ROOT(_sendq, WifiMergeRecord*, record);
                Timestamp early = Timestamp::now() - record->scheduled_output();
                if (send_next_merge()) {
                    if (early > 0)
                        _early_merges++;
                }
            } else {
                _log->critical("mem usage is %u, but sendq is empty?!", _mem_usage);
                // set mem usage to 0 in an attempt to limp along despite this
                _mem_usage = 0;
            }
        }
    } else {
        // add_packet() fails if the packet is too old and is presumed to be a
        // duplicate of a (merged) packet previously sent
        Packet *q = record->make_dupe_packet(p);
        if (q) {
            UNFOCUS();  // todo
            checked_output_push(1, q);
            FOCUS();  // todo
        } else {
            _log->strerror("make_dupe_packet() for packet 0x%08x", hash);
        }
    }

    // todo
    UNFOCUS();
}

bool
WifiMerge::run_task(Task *)
{
    FOCUS();  // todo
    bool worked = do_task_work(true);
    UNFOCUS();  // todo
    return worked;
}

void
WifiMerge::run_timer(Timer *)
{
    FOCUS();  // todo
    // schedule task to do some work
    (void) do_task_work(false);

    // and repeat after a fixed interval
    _timer.reschedule_after_msec(WIFIMERGE_TIMER_INTERVAL_MS);
    UNFOCUS();  // todo
}

/*
 * Private Methods
 */

bool
WifiMerge::do_task_work(bool in_task)
{
    // pop off and handle the first WifiMergeRecord if its ready to be sent
    Timestamp now = Timestamp::now();

    if (HEAP_COUNT(_sendq) > 0) {
        WifiMergeRecord *record = NULL;
        HEAP_ROOT(_sendq, WifiMergeRecord*, record);

        if (record->scheduled_output() <= now) {
            (void) send_next_merge();

            // that's enough work for one task execution - reschedule task to do
            // the rest
            // todo - handle >1 packet per task execution?
            if (in_task)
                _task.fast_reschedule();
            else
                _task.reschedule();
            return true;
        }
    }

    // pop off and handle the first WifiMergeRecord if its ready to be expired
    while (_expireq.size() > 0) {
        ExpirationTicket ticket = _expireq.front();

        // Check that this record is still empty (and thus is waiting to be
        // expired) - this is because a record could be scheduled for expiration
        // when a new packet comes in and with a matching hash.  Ideally the
        // record would be pulled out of the expiration queue when that happens
        // but that's expensive - much cheaper to just detect it right now.
        if (!ticket.record->is_empty()) {
            _expireq.pop_front();
            continue;
        }

        // Next check that the record's expiration time actually matches the
        // expiry time in the ExpirationTicket.  If these are different, that
        // means that the record was enqueued for expiration, and then was
        // re-activated (by an arriving packet), and then was re-scheduled for
        // expiration (by outputting a merged packet), all before its
        // ExpirationTicket reached the front of the _expireq.  So in this
        // state, there are actually two ExpirationTickets currently enqueued
        // for the same record, but only the latter one is valid and the early
        // one should be thrown away and ignored.
        if (ticket.expiry != ticket.record->expiration_time()) {
            // expiration times should only ever increase
            assert(ticket.expiry < ticket.record->expiration_time());
            _expireq.pop_front();
            continue;
        }

        // We have reached the point of the queue where records' expiration
        // times haven't been reached yet - quit until next timer tick
        if (ticket.expiry > now)
            return false;

        _log->debug("record for hash 0x%08x expired", ticket.record->hash());
        _expireq.pop_front();
        _record_map.erase(ticket.record->hash());
        delete ticket.record;

        // that's enough work for one task execution - reschedule task to do
        // the rest
        // todo - handle >1 packet per task execution?
        if (in_task)
            _task.fast_reschedule();
        else
            _task.reschedule();
        return true;
    }

    return false;
}

bool
WifiMerge::send_next_merge()
{
    WifiMergeRecord *record = NULL;
    HEAP_EXTRACT_ROOT(_sendq, WifiMergeRecord*, record);

    _log->debug("record for hash 0x%08x timeout; sending merged packet",
        record->hash());

    uint32_t merged_pkts, merged_mem;
    Packet *p = record->make_merged_packet(&merged_pkts, &merged_mem);
    if (!p) {
        _log->strerror("make_merged_packet");
        return false;
    }

    _log->debug("merged %u packets from hash 0x%08x record", merged_pkts,
        record->hash());
    _merge_in_count += merged_pkts;
    _merge_out_count++;
    assert(_stored_packets >= merged_pkts);
    _stored_packets -= merged_pkts;
    assert(_mem_usage >= merged_mem);
    _mem_usage -= merged_mem;

    if (record->is_empty()) {
        // no more packets in this record; add it to the expiration queue
        Timestamp expiration = Timestamp::now() + _expire_timeout;
        record->set_expiration(expiration);
        _expireq.push_back(ExpirationTicket(record));
    } else {
        // more packets to deal with; re-enqueue it to the send queue
        HEAP_ADD(_sendq, WifiMergeRecord*, record);
    }

    UNFOCUS();  // todo
    output(0).push(p);
    FOCUS();  // todo
    return true;
}

/*
 * Static Class Methods
 */

uint32_t
WifiMerge::hash_packet(const Packet *p)
{
    // Its tempting to use the packet's FCS field, but the FreeBSD ath driver
    // seems to drop the FCS from a small (but non-trivial) percentage of
    // capture packets.  However, it luckily does the right thing and does NOT
    // set the has-fcs radiotap flag in these cases.  Regardless, we just
    // calculate our own crc32 to use as the hash in every case.
    return wifi_calc_crc32(p->data(), p->length());
}

String
WifiMerge::read_handler(Element *e, void *thunk)
{
    const WifiMerge *elt = static_cast<WifiMerge *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RECORD_COUNT:
        return String(elt->_record_map.size());
    case H_SEND_LEN:
        return String(HEAP_COUNT(elt->_sendq));
    case H_EXPIRE_LEN:
        return String(elt->_expireq.size());
    case H_AVG_MERGE:
        if (elt->_merge_out_count == 0)
            return String("0");
        else {
            char cbuf[32];
            snprintf(cbuf, sizeof(cbuf), "%.4f", ((double)elt->_merge_in_count)/elt->_merge_out_count);
            return String(cbuf);
        }
    case H_COUNTS:
        return String(_net_allocs);
    case H_EXP_PACKET_COUNT: {
        HashMap<uint32_t, WifiMergeRecord*>::const_iterator iter = elt->_record_map.begin();
        int c = 0;
        for (; iter != elt->_record_map.end(); iter++)
            c += iter.value()->packet_count();
        return String(c);
    }
    case H_MIN_PACKET: {
        WifiMergeRecord *record = NULL;
        HEAP_ROOT(elt->_sendq, WifiMergeRecord*, record);
        if (record == NULL)
            return "0";
        else
            return record->scheduled_output().unparse();
    }
    default:
        return "internal error (bad thunk value)";
    }
}

int
WifiMerge::write_handler(const String &, Element *e, void *thunk,
    ErrorHandler *errh)
{
    WifiMerge *elt = static_cast<WifiMerge *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET:
        elt->_early_merges = 0;
        elt->_merge_in_count = 0;
        elt->_merge_out_count = 0;
        return 0;
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

// restore default HEAP_COMPARE definition
#undef HEAP_COMPARE
#define HEAP_COMPARE(a, b) HEAP_DEFAULT_COMPARE(a, b)

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(WifiMerge)
