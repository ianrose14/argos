/*
 * wifioverlay.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifioverlay.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "iputil.hh"
#include "argos/anno.h"
CLICK_DECLS

#define MAX_STICKY_WARNINGS 1  /* per BSSID */
      
/*
 * WifiOverlay Methods
 */
WifiOverlay::WifiOverlay()
    : _routes_warmup(120, 0), _routes_min_duration(60, 0), _sticky_routes(false),
      _counts_timer(this), _counts_interval(1,0), _wait_queues_total(0),
      _wait_queue_capac(100), _log_detailed_counts(true), _log(NULL)
{
}

WifiOverlay::~WifiOverlay()
{
    if (_log != NULL) delete _log;
}

enum { H_ASSIGNED_BSSIDS, H_NOROUTE_BSSIDS, H_NOROUTE_COUNT, H_ROUTES,
       H_ROUTE_COUNT, H_HANDLER_WRITE };

void
WifiOverlay::add_handlers()
{
    add_read_handler("assigned_bssids", read_handler, (void*)H_ASSIGNED_BSSIDS);
    add_read_handler("noroute_bssids", read_handler, (void*)H_NOROUTE_BSSIDS);
    add_read_handler("noroute_count", read_handler, (void*)H_NOROUTE_COUNT);
    add_read_handler("route_count", read_handler, (void*)H_ROUTE_COUNT);
    set_handler("route_query", Handler::OP_READ | Handler::READ_PARAM, query_handler);
    add_read_handler("routes", read_handler, (void*)H_ROUTES);
    add_write_handler("proxy_handler_write", write_handler, (void*)H_HANDLER_WRITE);
}

void *
WifiOverlay::cast(const char *n)
{
    if (strcmp(n, "WifiOverlay") == 0)
        return (WifiOverlay *)this;
    else
        return 0;
}

int
WifiOverlay::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String coordinator, loglevel, netlog;
    String logelt = "loghandler";
    Element *elt = NULL;

    if (cp_va_kparse(conf, this, errh,
            "COORDINATOR", cpkP+cpkM, cpString, &coordinator,
            "TRACKER", cpkM, cpElement, &elt,
            "LOCAL_IP", cpkM, cpIPAddress, &_local_ip,
            "WAITQUEUE_CAPAC", 0, cpUnsigned, &_wait_queue_capac,
            "COUNTS_INTERVAL", 0, cpTimestamp, &_counts_interval,
            "ROUTES_WARMUP", 0, cpTimestamp, &_routes_warmup,
            "ROUTES_MIN_DURATION", 0, cpTimestamp, &_routes_min_duration,
            "STICKY_ROUTES", 0, cpBool, &_sticky_routes,
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

    if (coordinator == "self") {
        // the coordinator IP should only used by clients, so, since I am the
        // coordinator, I should never use it - we set it to 0.0.0.0 just to
        // make sure it has a consistent value in case we need to debug
        _coordinator_ip = IPAddress("0.0.0.0");
        _am_coordinator = true;
        _log->info("I am the overlay coordinator!");
    } else {
        // assume coordinator is either a hostname or an IP address - either
        // way, ip_lookup_address() will return the IP it maps to
        if (ip_lookup_address(coordinator, &_coordinator_ip, errh) != 0)
            return -EINVAL;

        _am_coordinator = false;
        _log->info("coordinator address is %s",
            _coordinator_ip.unparse().c_str());
    }

    // check that elt is a pointer to an AssocTracker element
    _assoc_tracker = (AssocTracker*)elt->cast("AssocTracker");
    if (_assoc_tracker == NULL)
        return errh->error("TRACKER element is not an AssocTracker");

    if (!_sticky_routes)
        return errh->error("STICKY_ROUTES=false is not currently supported");

    return 0;
}

int
WifiOverlay::initialize(ErrorHandler *)
{
    Timestamp now = Timestamp::now();
    _counts_timer.initialize(this);
    _counts_timer.schedule_after(_counts_interval);
    _last_counts_time = now;
    _routes_start = now + _routes_warmup;
    return 0;
}

void
WifiOverlay::push(int, Packet *p)
{
    // decrement its TTL - if it hits 0 we will still process it locally (if its
    // destined for us), but if its destined for a remote node then it should be
    // dropped by a downstream element before its transferred
    uint8_t ttl = TTL_ANNO(p);
    if (ttl == 0) {
        _log->error("received packet (type=%d) with TTL=0", p->packet_type_anno());
    } else {
        SET_TTL_ANNO(p, ttl-1);
    }

    // for received packets, the MISC_IP anno should hold the SENDER address
    IPAddress src = IPAddress(MISC_IP_ANNO(p));

    if (p->packet_type_anno() == Packet::OUTGOING) {
        // this packet is a control message (as opposed to a captured packet) -
        // confirm that the ARGOS_CTRL annotation appears well-formed
        struct argos_ctrl *ctrl = ARGOS_CTRL_ANNO(p);

        if (ntohl(ctrl->magic) != ARGOS_CTRL_MAGIC) {
            _log->critical("packet received with pkt-type=OUTGOING but no"
                " ARGOS_CTRL anno (src=%s)", src.unparse().c_str());
            p->kill();
            return;
        }

        uint16_t type = ntohs(ctrl->type);
        if (type != ARGOS_CTRL_ANNO_OVERLAY_TYPE) {
            _log->critical("control message received with unrecognized type %hu (src=%s)",
                type, src.unparse().c_str());
            p->kill();
            return;
        }

        uint16_t subtype = ntohs(ctrl->subtype);
        switch (subtype) {
        case ARGOS_OVERLAY_SUBTYPE_COUNTS:
            process_counts(p, &src);
            break;

        case ARGOS_OVERLAY_SUBTYPE_ROUTES:
            process_routes(p, &src);
            break;

        case ARGOS_OVERLAY_SUBTYPE_PING:
            _log->debug("recv'd Ping from %s", src.unparse().c_str());
            // do nothing
            p->kill();
            break;

        case ARGOS_OVERLAY_SUBTYPE_HANDLER: {
            process_handler_request(p);
            break;
        }
        default:
            _log->critical("control message received with unrecognized subtype %hu from %s",
                subtype, src.unparse().c_str());
            p->kill();
            break;
        }
        return;
    }

    // else, assume this must be a captured packet...
    // now extract its BSSID to determine where to route it:

    // note: I have seen the BSSID 00:00:00:00:00:00 in the wild (specifically,
    // some Meraki device near citysense004 seems to use it) so it is NOT
    // necessarily an error if the inferred bssid == EtherAddress()
    EtherAddress bssid;
    if (_assoc_tracker->infer_bssid(p, &bssid) == false) {
        // If we can't determine the BSSID, then output this packet with the
        // special destination address "0.0.0.0" and let downstream elements
        // decide what to do with it
        _log->debug("routing packet to 0.0.0.0 (unable to infer BSSID) ts=%s",
            p->timestamp_anno().unparse().c_str());
        p->set_dst_ip_anno(IPAddress("0.0.0.0"));
        checked_output_push(0, p);
        return;
    }

    // the coordinator should not receive captured packets (note that this is
    // specific to our deployment 
    if (_am_coordinator) {
        // check if we know where this BSSID *should* route to
        IPAddress *sniffer = _bss_mappings.findp(bssid);

        if (sniffer == NULL)
            _log->warning("unexpectedly recv'd captured packet from %s with"
                " BSSID %s (route=NULL)", src.unparse().c_str(),
                bssid.unparse_colon().c_str());
        else
            _log->warning("unexpectedly recv'd captured packet from %s with"
                " BSSID %s (route=%s)", src.unparse().c_str(),
                bssid.unparse_colon().c_str(), sniffer->unparse().c_str());
        p->kill();
        return;
    }

    // As a special case, if this packet uses the broadcast BSSID
    // (FF:FF:FF:FF:FF:FF), then output it with the special destination address
    // 0.0.0.1 and let downstream elements decide what to do with it.
    // This is done because it would be relatively meaningless (and very
    // expensive) to aggregate all broadcast frames together at one sniffer like
    // we do for other BSSIDs.
    if (bssid.is_broadcast()) {
        // it makes no sense if a broadcast packet is received over the overlay;
        // they should all be locally captured
        if (p->packet_type_anno() == Packet::OTHERHOST)
            _log->error("packet received with broadcast BSSID and pkt-type=OTHERHOST");

        _log->debug("routing packet to 0.0.0.1 (BSSID=%s) ts=%s",
            bssid.unparse_colon().c_str(), p->timestamp_anno().unparse().c_str());
        p->set_dst_ip_anno(IPAddress("0.0.0.1"));
        checked_output_push(0, p);
        return;
    }

    if (p->packet_type_anno() == Packet::HOST) {
        // only updates BSSID-counts from packets that were captured locally
        PktCounter *count = _bss_counts.findp(bssid);
        if (count == NULL) {
            PktCounter c;
            c.incr(p);
            bool is_new = _bss_counts.insert(bssid, c);
            assert(is_new == true);
        } else {
            count->incr(p);
        }
    }

    // do we know which sniffer is in charge of this BSSID?
    IPAddress *sniffer = _bss_mappings.findp(bssid);

    if (sniffer == NULL) {
        // don't know where to send this packet - save it until we find out from
        // the coordinator
        DEQueue<Packet*> *queue = _wait_queues.findp(bssid);
        if (queue == NULL) {
            bool is_new = _wait_queues.insert(bssid, DEQueue<Packet*>());
            assert(is_new == true);
            queue = _wait_queues.findp(bssid);
            assert(queue != NULL);
        }

        if (queue->size() >= (int)_wait_queue_capac) {
            // overlay drop from wait-queues
            checked_output_push(1, p);
        } else {
            queue->push_back(p);
            _wait_queues_total++;
        }
    } else {
        // we know where to send this packet - annotate the packet's dst-IP with
        // the appropriate destination and then output the packet
        _log->debug("routing packet to %s (BSSID=%s) ts=%s",
            sniffer->unparse().c_str(), bssid.unparse_colon().c_str(),
            p->timestamp_anno().unparse().c_str());
        p->set_dst_ip_anno(*sniffer);
        checked_output_push(0, p);
    }
}

void
WifiOverlay::run_timer(Timer *)
{
    Timestamp now = Timestamp::now();

    if (_am_coordinator) {
        // the coordinator also uses this timer to check for route changes
        if (now >= _routes_start) {
            _log->debug("crunch-counts-timer fired");
            crunch_received_counts();
        } else {
            _log->debug("crunch-counts-timer fired, but still in warmup period");
        }
    } else {
        _log->debug("counts-timer fired");
        Timestamp elapsed = now - _last_counts_time;
        send_counts(&_last_counts_time, &elapsed);
    }

    // 'schedule_after', not 'reschedule_after'
    _counts_timer.schedule_after(_counts_interval);
    _last_counts_time = now;
}

uint32_t
WifiOverlay::assigned_bssids_count() const
{
    uint32_t count=0;
    HashMap<EtherAddress, IPAddress>::const_iterator iter = _bss_mappings.begin();
    for (; iter != _bss_mappings.end(); iter++) {
        if (iter.value() == _local_ip)
            count++;
    }
    return count;
}

void
WifiOverlay::crunch_received_counts()
{
    uint32_t new_routes = 0;
    uint32_t changed_routes = 0;

    assert(_sticky_routes);

    /*
     * TODO
     * - when routes change (either move or are created), send routing table
     *   diffs instead of the whole thing
     * - if the above is unreliable, then we could bcast the entire routing
     *   table to every peer every 1 minute or something to make sure that
     *   everyone syncs up eventually
     */
    HashMap<EtherAddress, FullNetCounts>::iterator iter = _count_records.begin();

    for (; iter != _count_records.end(); iter++) {
        EtherAddress bssid = iter.key();

        // look up current owner of this bssid
        IPAddress *owner = _bss_mappings.findp(bssid);

        // wait until at least one sniffer's count duration is at least
        // _routes_min_duration, and then we calculate the bytes/sec average for
        // each sniffer and make the sniffer with the highest value becomes the
        // owner of this bssid - if the traffic from this BSSID is bursty this
        // method could go wrong (oh well)
        double best_pkts_per_sec = 0;
        double best_bytes_per_sec = 0;
        uint32_t best_total_pkts = 0;
        IPAddress best_src;
        double owner_pkts_per_sec = 0;
        double owner_bytes_per_sec = 0;
        uint32_t owner_total_pkts = 0;
        Timestamp max_duration = Timestamp(0,0);

        assert(iter.value().size() > 0);

        FullNetCounts::const_iterator ip_iter = iter.value().begin();
        for (; ip_iter != iter.value().end(); ip_iter++) {
            IPAddress src = ip_iter.key();
            CountRecord c = ip_iter.value();

            double d = c.duration.doubleval();
            assert(d > 0);
            double pkt_rate = c.pkt_count / d;
            double byte_rate = c.byte_count / d;

            // important to check '>=' rather than just '>' so that if all of
            // the counts are 0 (because a sniffer has packets waiting for a
            // roue for this BSSID, but the sniffer isn't actually capturing any
            // new packets from this BSSID currently), a route will still get
            // assigned for this BSSID
            if (byte_rate >= best_bytes_per_sec) {
                best_src = src;
                best_pkts_per_sec = pkt_rate;
                best_bytes_per_sec = byte_rate;
                best_total_pkts = c.pkt_count;
            }

            if ((owner != NULL) && (src == *owner)) {
                owner_pkts_per_sec = pkt_rate;
                owner_bytes_per_sec = byte_rate;
                owner_total_pkts = c.pkt_count;
            }

            if (c.duration > max_duration)
                max_duration = c.duration;
        }

        if (max_duration < _routes_min_duration) {
            // if none of the sniffers had a long enough total duration, do not
            // create a new route for this BSSID yet
            continue;
        }

        // erase all stored counts for this bssid - important to do this now
        // before any subsequent checks (which might call 'continue' to break
        // out of this loop iteration)
        _count_records.erase(bssid);

        assert(best_src != IPAddress());  // should never happen

        if (owner == NULL) {
            if (best_total_pkts == 0) {
                assert(best_pkts_per_sec == 0);
                _log->warning("%s chosen as best route for %s with pkt_count=0",
                    best_src.unparse().c_str(), bssid.unparse_colon().c_str());
            } else {
                _log->info("creating new route for %s to %s (pkt-rate=%.2f, kbyte-rate=%.2f)",
                    bssid.unparse_colon().c_str(), best_src.unparse().c_str(),
                    best_pkts_per_sec, best_bytes_per_sec/1024);
            }

            _bss_mappings.insert(bssid, best_src);
            new_routes++;
        } else {
            if (*owner == best_src) {
                // all is well - the current owner is still the best owner for
                // this BSSID
                continue;
            }

            // As a hysterisis mechanism, we only want to change routes if some
            // peer is at least 25% AND 10 Kb/s "better" (more captured traffic)
            // than the current route - the second requirement is used to
            // prevent route changes for insignificant traffic differences
            // (e.g. 100 bytes/s vs. 50 bytes/s)
            if ((best_bytes_per_sec < (owner_bytes_per_sec * 1.25)) ||
                (best_bytes_per_sec < (owner_bytes_per_sec + 10240))) {
                continue;
            }

            // current owner is no longer the best choice
            if (_sticky_routes) {
                int stickies = _sticky_warnings.find(bssid);  // default: 0
                if (stickies < MAX_STICKY_WARNINGS) {
                    _log->info("sticky routes prevent updating route for %s"
                        " from %s (pkt-rate=%.2f, kbyte-rate=%.2f) to %s"
                        " (pkt-rate=%.2f, kbyte-rate=%.2f)",
                        bssid.unparse_colon().c_str(), owner->unparse().c_str(),
                        owner_pkts_per_sec, owner_bytes_per_sec/1024,
                        best_src.unparse().c_str(),
                        best_pkts_per_sec, best_bytes_per_sec/1024);
                    _sticky_warnings.insert(bssid, stickies+1);
                }
                // else, don't log anything to prevent spammage
            }
            else {
                // change route to new owner
                _log->info("updating route for %s from %s (pkt-rate=%.2f,"
                    " kbyte-rate=%.2f) to %s (pkt-rate=%.2f, kbyte-rate=%.2f)",
                    bssid.unparse_colon().c_str(), owner->unparse().c_str(),
                    owner_pkts_per_sec, owner_bytes_per_sec/1024,
                    best_src.unparse().c_str(),
                    best_pkts_per_sec, best_bytes_per_sec/1024);

                _bss_mappings.insert(bssid, best_src);
                changed_routes++;
            }
        }
    }

    if ((new_routes > 0) || (changed_routes > 0)) {
        _log->info("created %d new routes; updated %d routes", new_routes,
            changed_routes);

        // send the updated routing table to all peers
        IPAddress dst = IPAddress::make_broadcast();
        send_routes(&dst);
    }
    // else, routing table didn't change at all - no need to send it
}

String
WifiOverlay::dump_routing_table() const
{
    StringAccum sa = StringAccum(2048);
    HashMap<EtherAddress, IPAddress>::const_iterator iter = _bss_mappings.begin();
    for (; iter != _bss_mappings.end(); iter++) {
        sa << iter.key().unparse_colon() << " -> " << iter.value().unparse() << "\n";
    }

    return sa.take_string();
}

void
WifiOverlay::process_counts(Packet *p, const IPAddress *src)
{
    struct argos_ctrl *ctrl = ARGOS_CTRL_ANNO(p);
    uint16_t type = ntohs(ctrl->type);
    uint16_t subtype = ntohs(ctrl->subtype);

    assert(type == ARGOS_CTRL_ANNO_OVERLAY_TYPE);
    assert(subtype == ARGOS_OVERLAY_SUBTYPE_COUNTS);

    // only the coordinator should receive counts messages
    if (!_am_coordinator) {
        _log->warning("unexpectedly recv'd counts message from %s",
            src->unparse().c_str());
        p->kill();
        return;
    }

    // todo - garbage collect old entries from _count_records

    struct argos_overlay_countset *countset = (struct argos_overlay_countset*)p->data();

    Timestamp pkt_ts = Timestamp::make_usec(ntohl(countset->time_sec),
        ntohl(countset->time_usec));
    Timestamp duration = Timestamp::make_msec(ntohl(countset->duration_msec));

    if (duration == Timestamp(0,0)) {
        _log->error("Counts received from %s with a duration of 0 (pkt_ts=%s)",
            src->unparse().c_str(), pkt_ts.unparse().c_str());
        return;
    }

    uint32_t num_counts = ntohl(countset->elts);
    struct argos_overlay_count *counts =
        (struct argos_overlay_count*)(p->data() + sizeof(struct argos_overlay_countset));

    assert(p->length() >= (sizeof(struct argos_overlay_countset) +
            num_counts*sizeof(struct argos_overlay_count)));

    Timestamp delay = Timestamp::now() - pkt_ts;
    _log->debug("recv'd %d BSSID counts from %s (ts=%s, dur=%s)",
        num_counts, src->unparse().c_str(), pkt_ts.unparse().c_str(),
        duration.unparse().c_str());

    for (uint32_t i=0; i < num_counts; i++) {
        EtherAddress bssid = EtherAddress(counts[i].bssid);
        FullNetCounts *ip2counts = _count_records.findp(bssid);

        if (ip2counts == NULL) {
            _count_records.insert(bssid, FullNetCounts());
            ip2counts = _count_records.findp(bssid);
            assert(ip2counts != NULL);
        }

        uint32_t pkt_count = ntohl(counts[i].pkt_count);
        uint32_t byte_count = ntohl(counts[i].byte_count);

        if (_log_detailed_counts)
            _log->debug("peer %s reports %u packets (%u bytes) from %s",
                src->unparse().c_str(), pkt_count, byte_count,
                bssid.unparse_colon().c_str());

        CountRecord *rec = ip2counts->findp(*src);
        if (rec == NULL) {
            CountRecord cr = CountRecord();
            cr.duration = duration;
            cr.pkt_count = pkt_count;
            cr.byte_count = byte_count;
            ip2counts->insert(*src, cr);
        } else {
            rec->duration += duration;
            rec->pkt_count += pkt_count;
            rec->byte_count += byte_count;
        }
    }

    p->kill();
}

void
WifiOverlay::process_handler_request(Packet *p)
{
    struct argos_overlay_handler_write *ptr =
        (struct argos_overlay_handler_write *)p->data();

    StoredErrorHandler errh = StoredErrorHandler();

    String handler_name = String(ptr->handler_name);
    Element *elt;
    const Handler *handler;
    if (!cp_handler(handler_name, Handler::OP_WRITE, &elt, &handler, this, &errh)) {
        _log->warning("bad handler-write message: cannot parse handler name: %s",
            handler_name.c_str());
        p->kill();
        return;
    }

    int rv = handler->call_write(String(ptr->args), elt, &errh);
    if (rv < 0)
        _log->warning("remote handler-write request to %s failed: %s",
            handler_name.c_str(), errh.get_last_error().c_str());

    p->kill();
}

// note: this method deals with 2 different packet variables: the argument to
// the function (which is a ROUTES control message) and a local variable used
// when popping packets off of wait-queues.  If the argument to this method is
// named 'p' (as is standard practice) I tend to introduce bugs into the code
// by referring to 'p' when I mean to refer to the local variable.  So we'll
// name *neither* of them 'p' to avoid this.
void
WifiOverlay::process_routes(Packet *ctrlp, const IPAddress *src)
{
    struct argos_ctrl *ctrl = ARGOS_CTRL_ANNO(ctrlp);
    uint16_t type = ntohs(ctrl->type);
    uint16_t subtype = ntohs(ctrl->subtype);

    assert(type == ARGOS_CTRL_ANNO_OVERLAY_TYPE);
    assert(subtype == ARGOS_OVERLAY_SUBTYPE_ROUTES);

    // the coordinator should not receive routes messages
    if (_am_coordinator) {
        _log->warning("unexpectedly recv'd routes message from %s",
            src->unparse().c_str());
        ctrlp->kill();
        return;
    }

    struct argos_overlay_routeset *routeset =
        (struct argos_overlay_routeset*)ctrlp->data();
    uint32_t route_count = ntohl(routeset->route_count);

    _log->info("recv'd %d routes from %s", route_count, src->unparse().c_str());

    struct argos_overlay_route *routes = (struct argos_overlay_route*)
        (ctrlp->data() + sizeof(struct argos_overlay_routeset));

    assert(ctrlp->length() >= (sizeof(struct argos_overlay_routeset) +
            route_count*sizeof(struct argos_overlay_route)));

    for (uint32_t i=0; i < route_count; i++) {
        EtherAddress bssid = EtherAddress(routes[i].bssid);
        IPAddress dst = IPAddress(ntohl(routes[i].peer_ip));
        bool is_new = _bss_mappings.insert(bssid, dst);

        _log->debug("inserted route for bssid %s to %s",
            bssid.unparse_colon().c_str(), dst.unparse().c_str());

        if (is_new) {
            // check for packets that were waiting for a route
            DEQueue<Packet*> *deq = _wait_queues.findp(bssid);
            if (deq != NULL) {
                while (deq->size() > 0) {
                    Packet *q = deq->front();
                    deq->pop_front();
                    _wait_queues_total--;
                    _unrouted_count.erase(bssid);

                    // TODO - check that bssid still equals infer_bssid?

                    // now that we know where to send this packet, send it along
                    _log->debug("routing packet to %s (BSSID=%s) ts=%s",
                        dst.unparse().c_str(), bssid.unparse_colon().c_str(),
                        q->timestamp_anno().unparse().c_str());
                    q->set_dst_ip_anno(dst);
                    checked_output_push(0, q);
                }
                bool deleted = _wait_queues.erase(bssid);
                assert(deleted == true);
            }
        }
    }

    // done with packet
    ctrlp->kill();

    // lastly, check for any packets that are still waiting for a route -
    // typically this should not happen (because any such packets should have
    // been reported in our last counts messge, and the coordinator then should
    // have responded with a route for that BSSID) but its possible with careful
    // timing if the packets arrive after our last counts message was sent but
    // before the routes arrive from the coordinator
    assert((_wait_queues.size() > 0) == (_wait_queues_total > 0));

    HashMap<EtherAddress, DEQueue<Packet*> >::const_iterator iter =
        _wait_queues.begin();
    for (; iter != _wait_queues.end(); iter++) {
        int *iptr = _unrouted_count.findp(iter.key());
        if (iptr != NULL) {
            (*iptr)++;

            if ((*iptr) == 3) {
                _log->warning("BSSID %s is still unrouted after 3 routing table"
                    " updates (%d packets enqueued)",
                    iter.key().unparse_colon().c_str(), iter.value().size());
            }
        }
    }
}

void
WifiOverlay::send_counts(const Timestamp *now, const Timestamp *elapsed)
{
    // Ensure that we send a count for every BSSID that has packets waiting for
    // a route, even if we captured 0 of them over the past interval - this is
    // to make sure that the server considers those BSSIDs (and hopefully
    // creates a route for them).  If we do not do this, then the following bad
    // situation can happen: some packets are received for BSSID X and reported
    // to the server, but the server does not create a route right away, and if
    // no more packets are received, then the server will never revisit that
    // BSSID (and realize that enough time has passed that a route can be
    // created) and those initial packets will sit buffered forever waiting for
    // a route.
    HashMap<EtherAddress, DEQueue<Packet*> >::const_iterator iter =
        _wait_queues.begin();
    for (; iter != _wait_queues.end(); iter++) {
        PktCounter *count = _bss_counts.findp(iter.key());
        if (count == NULL) {
            bool is_new = _bss_counts.insert(iter.key(), PktCounter());
            assert(is_new == true);
        }
    }

    int num_counts = _bss_counts.size();

    if (num_counts == 0) {
        _log->debug("no need to send counts - no packets captured and no wait-queues");
        return;
    }

    _log->debug("sending counts for %d BSSIDs", num_counts);

    size_t reqlen = sizeof(struct argos_overlay_countset) +
        num_counts*sizeof(struct argos_overlay_count);

    u_char *buf = (u_char*)malloc(reqlen);
    if (buf == NULL) {
        _log->error("malloc(%d) failed: %s", reqlen, strerror(errno));
        return;
    }

    struct argos_overlay_countset *header = (struct argos_overlay_countset*)buf;
    header->time_sec = htonl((uint32_t)now->sec());
    header->time_usec = htonl(now->usec());
    header->duration_msec = htonl((uint32_t)(elapsed->msecval()));
    header->elts = htonl(num_counts);

    struct argos_overlay_count *elts =
        (struct argos_overlay_count*)(buf + sizeof(struct argos_overlay_countset));

    for (int i=0; i < num_counts; i++) {
        HashMap<EtherAddress, PktCounter>::iterator iter = _bss_counts.begin();
        assert(iter != _bss_counts.end());

        if (_log_detailed_counts)
            _log->debug("reporting %u packets (%u bytes) from %s",
                iter.value().pkt_count, iter.value().byte_count,
                iter.key().unparse_colon().c_str());

        memcpy(elts[i].bssid, iter.key().data(), 6);
        elts[i].pkt_count = htonl(iter.value().pkt_count);
        elts[i].byte_count = htonl(iter.value().byte_count);
        _bss_counts.erase(iter.key());
    }

    assert(_bss_counts.size() == 0);

    WritablePacket *p;
    try {
        p = Packet::make(0, buf, reqlen, 0);
    }
    catch (std::bad_alloc &ex) {
        p = NULL;
    }
    free(buf);

    if (p == NULL) {
        _log->error("failed to create Packet to carry counts message (size=%d)", reqlen);
        return;
    }

    send_control_message(p, &_coordinator_ip, ARGOS_OVERLAY_SUBTYPE_COUNTS);
}

int
WifiOverlay::send_handler_write(const IPAddress *dst, const String *handler_name,
    const String *args, ErrorHandler *errh)
{
    if (handler_name->length() >= ARGOS_OVERLAY_MAX_HANDLER_NAMELEN)
        return errh->error("handler name too long: %s", handler_name->c_str());

    if (args->length() >= ARGOS_OVERLAY_MAX_HANDLER_ARGSLEN)
        return errh->error("handler args too long: %s", args->c_str());

    size_t reqlen = sizeof(struct argos_overlay_handler_write);
    WritablePacket *p;
    try {
        p = Packet::make(0, NULL, reqlen, 0);
    }
    catch (std::bad_alloc &ex) {
        return errh->error("Packet::make() failed");
    }

    struct argos_overlay_handler_write *ptr =
        (struct argos_overlay_handler_write *)p->data();
    strlcpy(ptr->handler_name, handler_name->c_str(), sizeof(ptr->handler_name));
    strlcpy(ptr->args, args->c_str(), sizeof(ptr->args));

    send_control_message(p, dst, ARGOS_OVERLAY_SUBTYPE_HANDLER);
    return 0;
}

void
WifiOverlay::send_control_message(Packet *p, const IPAddress *dst, uint16_t subtype)
{
    struct argos_ctrl *ctrl = ARGOS_CTRL_ANNO(p);
    ctrl->magic = htonl(ARGOS_CTRL_MAGIC);
    ctrl->type = htons(ARGOS_CTRL_ANNO_OVERLAY_TYPE);
    ctrl->subtype = htons(subtype);
    p->set_packet_type_anno(Packet::OUTGOING);
    p->set_timestamp_anno(Timestamp::now());

    // currently, control messages should only ever take 1 hop (they are never
    // re-routed)
    SET_TTL_ANNO(p, 1);

    p->set_dst_ip_anno(*dst);
    checked_output_push(0, p);
}

void
WifiOverlay::send_ping(const IPAddress *dst)
{
    _log->debug("sending ping message to %s", dst->unparse().c_str());

    // packet itself carries no data; just the annotations matter
    WritablePacket *p;
    try {
        p = Packet::make(10);
    }
    catch (std::bad_alloc &ex) {
        _log->error("failed to create Packet to carry ping message to %s",
            dst->unparse().c_str());
        return;
    }

    send_control_message(p, dst, ARGOS_OVERLAY_SUBTYPE_PING);
}

void
WifiOverlay::send_routes(const IPAddress *dst)
{
    uint32_t num_routes = _bss_mappings.size();
    size_t reqlen = sizeof(struct argos_overlay_routeset) +
        num_routes*sizeof(struct argos_overlay_route);

    if (num_routes == 0) {
        _log->debug("no need to send routing table (no routes present)");
        return;
    }

    _log->debug("sending routing table to %s (%u bytes)", dst->unparse().c_str(),
        reqlen);

    u_char *buf = (u_char*)malloc(reqlen);
    if (buf == NULL) {
        _log->error("malloc(%d) failed: %s", reqlen, strerror(errno));
        return;
    }

    struct argos_overlay_routeset *header = (struct argos_overlay_routeset*)buf;
    header->route_count = htonl(num_routes);

    struct argos_overlay_route *routes =
        (struct argos_overlay_route*)(buf + sizeof(struct argos_overlay_routeset));

    HashMap<EtherAddress, IPAddress>::const_iterator iter = _bss_mappings.begin();
    for (uint32_t i=0; i < num_routes; i++) {
        assert(iter != _bss_mappings.end());
        memcpy(&routes[i].bssid, iter.key().data(), 6);
        routes[i].peer_ip = htonl(iter.value().addr());
        iter++;
    }

    WritablePacket *p;
    try {
        p = Packet::make(0, buf, reqlen, 0);
    }
    catch (std::bad_alloc &ex) {
        p = NULL;
    }
    free(buf);

    if (p == NULL) {
        _log->error("failed to create Packet to carry routes message (size=%d)", reqlen);
        return;
    }

    send_control_message(p, dst, ARGOS_OVERLAY_SUBTYPE_ROUTES);
}


/*
 * Static methods
 */

int
WifiOverlay::query_handler(int, String &s, Element *e, const Handler*, ErrorHandler *errh)
{
    WifiOverlay *elt = static_cast<WifiOverlay *>(e);
    EtherAddress ether, bssid;
    if (cp_ethernet_address(s, &ether, elt)) {
        IPAddress *ip = elt->_bss_mappings.findp(ether);
        if (ip == NULL)
            s = "";
        else
            s = ip->unparse();
        return 0;
    } else
        return errh->error("expected Ethernet address, not '%s'", s.c_str());
}

String
WifiOverlay::read_handler(Element *e, void *thunk)
{
    const WifiOverlay *elt = static_cast<WifiOverlay *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_ASSIGNED_BSSIDS:
        return String(elt->assigned_bssids_count());
    case H_NOROUTE_BSSIDS:
        return String(elt->_wait_queues.size());
    case H_NOROUTE_COUNT:
        return String(elt->_wait_queues_total);
    case H_ROUTES:
        return elt->dump_routing_table();
    case H_ROUTE_COUNT:
        return String(elt->_bss_mappings.size());
    default:
        return "internal error (bad thunk value)";
    }
}

int
WifiOverlay::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    WifiOverlay *elt = static_cast<WifiOverlay *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_HANDLER_WRITE: {
        // args: peer-IP, handler-name, args [...]
        IPAddress ip;
        String handler_name;

        Vector<String> fields;
        cp_spacevec(s_in, fields);
        int rv = cp_va_kparse(fields, elt, errh,
            "IP", cpkP, cpIPAddress, &ip,
            "HANDLER", cpkP, cpString, &handler_name,
            cpIgnoreRest, cpEnd);
        if (rv < 0) return -1;

        StringAccum sa;
        for (int i=rv; i < fields.size(); i++)
            sa << fields[i] << " ";

        String args = sa.take_string();
        return elt->send_handler_write(&ip, &handler_name, &args, errh);
    }
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(IPUtil)
EXPORT_ELEMENT(WifiOverlay)
