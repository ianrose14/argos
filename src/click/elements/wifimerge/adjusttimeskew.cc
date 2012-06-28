/*
 * adjusttimeskew.{cc,hh} -- sync timestamps of packets from multiple sources.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "adjusttimeskew.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include "../argos/anno.h"
#include "wifimerge.hh"

CLICK_DECLS


#define ADJSKEW_MAX_WINDOW 50

AdjustTimeSkew::AdjustTimeSkew()
    : _end_warmup(0,0), _warmup_dur(0,0), _winsize(11)
{
}

AdjustTimeSkew::~AdjustTimeSkew()
{
    delete _workspace;
    if (_log != NULL) delete _log;
}

enum { H_BASE_IP, H_DUMP_ALL_PAIRS, H_DUMP_BASE_PATHS };

void
AdjustTimeSkew::add_handlers()
{
    add_read_handler("base_ip", read_handler, (void*)H_BASE_IP);
    add_read_handler("dump_all_pairs", read_handler, (void*)H_DUMP_ALL_PAIRS);
    add_read_handler("dump_base_paths", read_handler, (void*)H_DUMP_BASE_PATHS);
}

int
AdjustTimeSkew::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "WARMUP", 0, cpTimestamp, &_warmup_dur,
            "WINDOW", 0, cpInteger, &_winsize,
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

    _workspace = new Timestamp[_winsize];
    assert(_workspace != NULL);

    return 0;
}

void
AdjustTimeSkew::push(int port, Packet *p)
{
    assert((port == 0) || (port == 1));

    if (port == 0) {
        // port 0 is for packets that need their timestamp adjusted to account
        // for sniffers' timeskew

        // first, save the sniffer's local capture time to the First-Timestamp
        // anno space
        SET_FIRST_TIMESTAMP_ANNO(p, p->timestamp_anno());

        // next, if this packet doesn't have an Argos sniffer annotation then
        // pass it on without changing the (main) packet timestamp
        const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
        struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;

        if (sniff->magic != ARGOS_SNIFF_MAGIC) {
            _log->error("packet received on port 1 with no Argos-Sniff annotation");
            output(0).push(p);
            return;
        }

        IPAddress src = IPAddress(sniff->sniffer);

        if (_base_ip == IPAddress()) {
            if (_end_warmup.sec() == 0) {
                // apparently this is the very first packet received
                _end_warmup = p->timestamp_anno() + _warmup_dur;

                _log->debug("first packet received w/ ts %s; warmup expiration set to %s",
                    p->timestamp_anno().unparse().c_str(), _end_warmup.unparse().c_str());
            }

            if (p->timestamp_anno() < _end_warmup) {
                // during the warmup period just count packets from each sniffer but
                // don't adjust timestamps at all
                uint32_t *c = _counts.findp(src);
                if (c == NULL) {
                    _counts.insert(src, 1);
                } else {
                    (*c)++;
                }

                output(0).push(p);
                return;
            }

            // this must be the first packet received after the warmup period
            uint32_t max_count = 0;
            HashMap<IPAddress,uint32_t>::const_iterator iter = _counts.begin();
            for (; iter != _counts.end(); iter++) {
                if (iter.value() > max_count) {
                    max_count = iter.value();
                    _base_ip = iter.key();
                }
            }

            _counts.clear();

            // this case only occurs if the counts map was empty (e.g. because
            // the warmup period was 0s)
            if (_base_ip == IPAddress())
                _base_ip = src;

            _log->info("base IP set to %s (with recv-count of %u)",
                _base_ip.unparse().c_str(), max_count);
        }

        // estimate the time skew from the 'base' node to the sniffer that
        // captured this packet
        Timestamp est_skew, est_skew_err;
        if (!estimate_timeskew(src, &est_skew, &est_skew_err)) {
            // there is no path - use default values
            //_log->debug("no path found from %s to %s", src.unparse().c_str(), _base_ip.unparse().c_str());

            est_skew = Timestamp(0,0);
            est_skew_err = Timestamp::make_usec(0, DEF_TIMESKEW_ERR);
        }

        p->set_timestamp_anno(p->timestamp_anno() - est_skew);

        uint32_t val = est_skew_err.usecval();
        if (val > MAX_TIMESKEW_ERR) val = MAX_TIMESKEW_ERR;
        if (val < MIN_TIMESKEW_ERR) val = MIN_TIMESKEW_ERR;

        SET_TIMESKEW_ERR_ANNO(p, val);
        output(0).push(p);
    }
    else if (port == 1) {
        // port 1 is for merged packet that are passing through to update the
        // node-to-node timeskew measurements we use to make estimations
        struct argos_wifimerge *wf = (struct argos_wifimerge*)p->data();
        struct argos_wifimerge_elt *elts = (struct argos_wifimerge_elt*)
            (p->data() + sizeof(struct argos_wifimerge));

        if (wf->magic != ARGOS_WIFIMERGE_MAGIC) {
            _log->error("packet received on port 1 with no WifiMerge header");
            output(1).push(p);
            return;
        }

        for (int i=0; i < wf->num_elts; i++) {
            for (int j=(i+1); j < wf->num_elts; j++) {
                IPAddress a = IPAddress(elts[i].src);
                IPAddress b = IPAddress(elts[j].src);
                Timestamp skew = Timestamp(elts[i].ts) - Timestamp(elts[j].ts);

                // add both the forward and reverse paths
                add_skew_measurement(a, b, skew);
                add_skew_measurement(b, a, -skew);
            }
        }

        output(1).push(p);
    }
}

String
AdjustTimeSkew::read_handler(Element *e, void *thunk)
{
    const AdjustTimeSkew *elt = static_cast<AdjustTimeSkew *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_BASE_IP:
        return elt->_base_ip.unparse();

    case H_DUMP_ALL_PAIRS: {
        StringAccum sa;
        TimeSkewMap::const_iterator iter = elt->_skew_map.begin();
        for (; iter != elt->_skew_map.end(); iter++) {
            const TimeSkewList list = iter.value();
            for (int i=0; i < list.size(); i++) {
                sa << iter.key() << " -> " << list[i].ip <<
                    ": " << elt->get_median(&(list[i].skews)) << "\n";
            }
        }
        return sa.take_string();
    }
    case H_DUMP_BASE_PATHS: {
        if (elt->_base_ip == IPAddress())
            return "(no base-IP selected yet)";
        
        StringAccum sa;
        TimeSkewMap::const_iterator iter = elt->_skew_map.begin();
        for (; iter != elt->_skew_map.end(); iter++) {
            IPAddress ip = iter.key();
            Timestamp est_skew, est_skew_err;
            if (elt->estimate_timeskew(ip, &est_skew, &est_skew_err))
                sa << "ip=" << ip << " skew=" << est_skew
                   << " err=" << est_skew_err << "\n";
            else
                sa << "ip=" << ip << " skew=? err=?\n";
        }
        return sa.take_string();
    }
    default:
        return "internal error (bad thunk value)";
    }
}

void
AdjustTimeSkew::add_skew_measurement(IPAddress &src, IPAddress &dst,
    Timestamp skew)
{
    TimeSkewList *list = _skew_map.findp(src);
    if (list == NULL) {
        _skew_map.insert(src, TimeSkewList());
        list = _skew_map.findp(src);
        assert(list != NULL);
    }

    for (int i=0; i < list->size(); i++) {
        if ((*list)[i].ip == dst) {
            // found the list entry that is supposed to be updated
            DEQueue<Timestamp> *vals = &((*list)[i].skews);
            Timestamp old_skew = get_median(vals);
            bool first_skew_update = (vals->size() == 0);

            vals->push_back(skew);
            if (vals->size() > _winsize)
                vals->pop_front();

            assert((*list)[i].skews.size() > 0);

            if (!first_skew_update) {
                Timestamp new_skew = get_median(vals);
                Timestamp diff = new_skew - old_skew;

                // warn if the (median) skew estimate changes by more than <X>
                // ms -- note that this is different from (rarer than) warning
                // whenever an *individual* skew value is more than <X> ms
                // different from the current (median) skew estimate
                static const Timestamp thresh = Timestamp::make_msec(0, 100);

                if (diff.sec() < 0)
                    diff = -diff;

                if (diff > thresh)
                    _log->warning("skew from %s to %s updated from %s to %s"
                        "  (skews=%u)", src.unparse().c_str(), dst.unparse().c_str(),
                        old_skew.unparse().c_str(), new_skew.unparse().c_str(),
                        vals->size());
            }

            return;
        }
    }

    // dst not in the list, meaning this is the first timeskew measurement from
    // [src] to [dst] that we have received; append it
    list->push_back(IPAndSkew(dst));
    IPAndSkew dst_skews = list->back();
    assert(dst_skews.ip == dst);
    dst_skews.skews.push_back(skew);
    assert(dst_skews.skews.size() <= _winsize);

    _log->debug("new IP link discovered %s -> %s", src.unparse().c_str(), dst.unparse().c_str());
}

struct SkewAndErr {
    IPAddress ip;
    Timestamp skew, skew_err;
    SkewAndErr(IPAddress i, Timestamp a, Timestamp b) : ip(i), skew(a), skew_err(b) {}
};    

bool
AdjustTimeSkew::estimate_timeskew(IPAddress &dst, Timestamp *skew,
    Timestamp *skew_err) const
{
    // perform a breadth-first search for a "path" from _base_ip to dst - each
    // element in this queue is a pair representing the estimated time skew from
    // the base-IP to the specified IP
    DEQueue<SkewAndErr> q;

    SkewAndErr sae = SkewAndErr(_base_ip, Timestamp(0,0), Timestamp(0,0));
    q.push_back(sae);
    // the values in _skew_map form a graph (any node can be connected to any
    // other node), not a tree - so we need to keep track of which IPs we have
    // already processed so that we can ignore them if they appear again
    HashMap<IPAddress, int> processed_ips;  // value is ignored

    while (q.size() > 0) {
        SkewAndErr head = q.front();
        q.pop_front();
        // is this the destination IP we are looking for?
        if (head.ip == dst) {
            if (skew != NULL) *skew = head.skew;
            if (skew_err != NULL) *skew_err = head.skew_err;
            return true;
        }

        // have we already processed this IP?
        int *ptr = processed_ips.findp(head.ip);
        if (ptr != NULL)
            continue;
        processed_ips.insert(head.ip, 0);

        // iterate all IPs that are directly 'connected' to head.ip
        TimeSkewList *list = _skew_map.findp(head.ip);

        if (list != NULL) {
            for (int i=0; i < list->size(); i++) {
                Timestamp child_skew = get_median(&((*list)[i].skews));
                Timestamp child_skew_err = get_spread(&((*list)[i].skews));

                // At this point, the timeskew from base_ip to head.ip is head.skew,
                // and the timeskew from head.ip to child_ip is child_skew -- so the
                // timeskew from base_ip to child_ip should be (head.skew +
                // child_skew).  Also ditto all of that for skew-error, although
                // this is a conservative estimate as clock drifts may be
                // somewhat aligned and thus not quite "as bad" as additive.
                SkewAndErr elt = SkewAndErr((*list)[i].ip, head.skew + child_skew,
                    head.skew_err + child_skew_err);
                q.push_back(elt);
            }
        }
    }

    // if the queue runs out, then there is no path so we just give up
    return false;
}

Timestamp
AdjustTimeSkew::get_median(const DEQueue<Timestamp> *deq)
{
    Timestamp workspace[ADJSKEW_MAX_WINDOW];
    if (deq->size() == 0) return Timestamp(0);
    assert(deq->size() <= ADJSKEW_MAX_WINDOW);

    for (int i=0; i < deq->size(); i++)
        workspace[i] = (*deq)[i];
    click_qsort(workspace, deq->size());
    return workspace[deq->size() / 2];
}

Timestamp
AdjustTimeSkew::get_spread(const DEQueue<Timestamp> *deq) const
{
    if (deq->size() == 0) return Timestamp(0);

    Timestamp min_ts = (*deq)[0];
    Timestamp max_ts = (*deq)[0];

    for (int i=1; i < deq->size(); i++) {
        if ((*deq)[i] < min_ts)
            min_ts = (*deq)[i];
        if ((*deq)[i] > max_ts)
            max_ts = (*deq)[i];
    }

    return max_ts - min_ts;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(AdjustTimeSkew)
