/*
 * webrequesttracker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "webrequesttracker.hh"
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/wifi.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pcap/pcap.h>
#include <pktparse.h>
#include "../loghandler.hh"
#include "../setsniffer.hh"
#include "../wifiutil.hh"
CLICK_DECLS


// TCPFlowInfo methods

TCPFlowInfo::TCPFlowInfo()
{
    _src_mac = EtherAddress();
    _min_ts = Timestamp(0);
    _max_ts = Timestamp(0);
    _has_syn = _has_data = false;
    _flags = 0;
    _http_host = NULL;
    _cookie_domain = NULL;
    _search_queries = NULL;
    _search_queries_alloc = 0;
    _terminated = false;
}

TCPFlowInfo::TCPFlowInfo(EtherAddress &src_mac, Timestamp &ts)
{
    _src_mac = src_mac;
    _min_ts = ts;
    _max_ts = ts;
    _has_syn = _has_data = false;
    _flags = 0;
    _http_host = NULL;
    _cookie_domain = NULL;
    _search_queries = NULL;
    _search_queries_alloc = 0;
    _terminated = false;
}

TCPFlowInfo::~TCPFlowInfo()
{
    if (_http_host != NULL) free(_http_host);
    if (_cookie_domain != NULL) free(_cookie_domain);
    if (_search_queries != NULL) free(_search_queries);
}

void
TCPFlowInfo::terminate()
{
    assert(!_terminated);

    if (_http_host != NULL) {
        free(_http_host);
        _http_host = NULL;
    }
    if (_cookie_domain != NULL) {
        free(_cookie_domain);
        _cookie_domain = NULL;
    }
    if (_search_queries != NULL) {
        free(_search_queries);
        _search_queries = NULL;
    }
    _terminated = true;
}

// WebRequestTracker methods

// TODO - once crashes are resolved, increase timeout to 20*60
WebRequestTracker::WebRequestTracker()
    : _am_server(false), _node_id(0), _timer(this),
      _interval(30, 0), _timeout(3*60,0), _dlt(-1), _mem_used(0),
      _mem_high_thresh(1048576), _db(NULL), _log(NULL)
{
}

WebRequestTracker::~WebRequestTracker()
{
    if (_log != NULL) delete _log;
}

enum { H_MEM_USED, H_ACTIVE_SESSIONS, H_TIMEOUT_ALL };

void
WebRequestTracker::add_handlers()
{
    if (!_am_server) {
        add_read_handler("mem_size", read_handler, (void*)H_MEM_USED);
        add_read_handler("active_sessions", read_handler, (void*)H_ACTIVE_SESSIONS);
        add_write_handler("timeout_all", write_handler, (void*)H_TIMEOUT_ALL);
    }
}

int
WebRequestTracker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dlt_name;
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "DLT", 0, cpString, &dlt_name,
            "TIMEOUT", 0, cpTimestamp, &_timeout,
            "HIMEM", 0, cpUnsigned, &_mem_high_thresh,
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
        if (ninputs() != 1)
            return errh->error("when SERVER=true, element must have exactly 1 input");

        if (noutputs() != 0)
            return errh->error("when SERVER=true, element does not support outputs");
    }
    else {
        if (ninputs() != 2)
            return errh->error("when SERVER=false, element must have exactly 2 inputs");

        if (noutputs() == 0)
            return errh->error("when SERVER=false, element must have at least 1 output");

        _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
        if (_dlt < 0)
            return errh->error("bad datalink type");

        if ((_dlt != DLT_EN10MB) && (_dlt != DLT_IEEE802_11) && (_dlt != DLT_IEEE802_11_RADIO))
            return errh->error("datalink type not supported");
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
WebRequestTracker::initialize(ErrorHandler *)
{
    if (!_am_server) {
        _timer.initialize(this);
        _timer.reschedule_after(_interval);
    }
    return 0;
}

void
WebRequestTracker::push(int port, Packet *p)
{
    if (_am_server) {
        const struct argos_userweb_msg *msg = (const struct argos_userweb_msg*)p->data();

        if (p->length() < sizeof(struct argos_userweb_msg)) {
            _log->error("bad message received with length=%d and misc-ip=%s",
                p->length(), IPAddress(MISC_IP_ANNO(p)).unparse().c_str());
            p->kill();
            return;
        }

        if (ntohl(msg->magic) != ARGOS_WEBREQ_MSG_MAGIC) {
            _log->error("bad message received with magic=0x%08x and misc-ip=%s",
                ntohl(msg->magic), IPAddress(MISC_IP_ANNO(p)).unparse().c_str());
            p->kill();
            return;
        }

        int32_t node_id = ntohl(msg->node_id);
        EtherAddress src = EtherAddress(msg->src_mac);
        IPAddress dst_ip = IPAddress(msg->dst_ip);
        uint16_t dst_port = ntohs(msg->dst_port);
        Timestamp ts = Timestamp::make_usec(ntohl(msg->first_pkt_sec),
            ntohl(msg->first_pkt_usec));
        const char *host = "[none]";

        if (strlen(msg->http_host) > 0)
            host = msg->http_host;
        else if (strlen(msg->cookie_domain) > 0)
            host = msg->cookie_domain;

        _log->data("NEW-REQUEST  ts=%s src=%s dst=%s:%d host=%s sniffer=%d",
            ts.unparse().c_str(), src.unparse_colon().c_str(),
            dst_ip.unparse().c_str(), dst_port, host, node_id);

        // insert data into database (if we have a db handle)
        if (_db) {
            db_insert(node_id, ts, src, dst_ip, dst_port, msg->flags,
                msg->http_host, msg->cookie_domain, msg->search_queries);
        }

        // done!
        p->kill();
    } else {
        // !_am_server

        if (!p->has_transport_header()) {
            _log->error("packet received with no transport header marked");
            checked_output_push(1, p);
            return;
        }

        EtherAddress src_mac, dst_mac;
        if (!get_mac_addrs(p, &src_mac, &dst_mac)) {
            // packet is malformed somehow...
            checked_output_push(1, p);
            return;
        }

        const struct click_ip *ip_hdr = p->ip_header();
        const struct click_tcp *tcp_hdr = p->tcp_header();

        // do NOT check tcp port numbers here - we rely on external elements to
        // set that policy

        EtherAddress client_mac;
        IPFlowID flow_id;

        assert(port <= 1);

        if (port == 0) {
            // we expect client->server packets (i.e. http requests) on port 0
            client_mac = src_mac;
            flow_id = IPFlowID(IPAddress(ip_hdr->ip_src), tcp_hdr->th_sport,
                IPAddress(ip_hdr->ip_dst), tcp_hdr->th_dport);
        } else {
            // we expect server->client packets (i.e. http responses) on port 1
            client_mac = dst_mac;
            // reverse source and destination
            flow_id = IPFlowID(IPAddress(ip_hdr->ip_dst), tcp_hdr->th_dport,
                IPAddress(ip_hdr->ip_src), tcp_hdr->th_sport);
        }

        TCPFlowInfo *info = _sessions.findp(flow_id);
        if (info == NULL) {
            TCPFlowInfo new_info = TCPFlowInfo(client_mac, p->timestamp_anno());
            _sessions.insert(flow_id, new_info);
            info = _sessions.findp(flow_id);
            assert(info != NULL);
            _mem_used += info->mem_size();
            info->_sniffer_id = 0;
        }

        if ((info->_sniffer_id == 0) || ((info->_flags & ARGOS_WEBREQ_F_REQUEST) == 0)) {
            StoredErrorHandler errh;
            int32_t sniffer_id;
            if (SetSniffer::parse_sniffer_id(p, &sniffer_id, &errh) != 0) {
                _log->error("parse_sniffer_id failed: %s", errh.get_last_error().c_str());
            } else {
                info->_sniffer_id = sniffer_id;
            }
        }

        _mem_used -= info->mem_size();
        assert(_mem_used >= 0);
        process_packet(&flow_id, info, p, (port == 0));
        _mem_used += info->mem_size();

        // done with packet
        p->kill();

        if (info->_terminated) return;

        if (info->is_complete()) {
            _log->debug("completion of %s", flow_id.unparse().c_str());
            _mem_used -= info->mem_size();
            assert(_mem_used >= 0);
            send_message(flow_id, *info);
            info->terminate();
            _mem_used += info->mem_size();
        }

        if ((uint32_t)_mem_used >= _mem_high_thresh)
            shed_memory();
    }
}

void
WebRequestTracker::run_timer(Timer*)
{
    _timer.reschedule_after(_interval);

    // any session not heard from since this time will be timed out
    Timestamp min_time = Timestamp::now() - _timeout;

    HashMap<IPFlowID, TCPFlowInfo>::iterator iter = _sessions.begin();
    for (; iter != _sessions.end(); iter++) {
        if (iter.value()._max_ts < min_time) {
            // time out and delete this session, sending a message for it if we
            // have not yet already done so
            _mem_used -= iter.value().mem_size();
            assert(_mem_used >= 0);

            if (!iter.value()._terminated) {
                _log->debug("timeout for %s", iter.key().unparse().c_str());
                send_message(iter.key(), iter.value());
            }

            _sessions.erase(iter.key());
        }
    }
}

void
WebRequestTracker::shed_memory()
{
    // todo
    _log->warning("TODO: shed_memory()");
}

int
WebRequestTracker::timeout_all_sessions()
{
    int c = 0;

    HashMap<IPFlowID, TCPFlowInfo>::iterator iter = _sessions.begin();
    for (; iter != _sessions.end(); iter++) {
        // time out and delete this session, sending a message for it if we
        // have not yet already done so
        _mem_used -= iter.value().mem_size();
        assert(_mem_used >= 0);

        if (!iter.value()._terminated)
            send_message(iter.key(), iter.value());

        _sessions.erase(iter.key());
        c++;
    }
    return c;
}

// Private methods

void
WebRequestTracker::db_insert(int32_t node_id, const Timestamp &ts,
    const EtherAddress &src, const IPAddress &dst_ip, uint16_t dst_port,
    uint8_t flags, const char *http_host, const char *cookie_domain,
    const char *search_queries)
{
    Vector<const char*> values;

    static const String query = String("INSERT INTO web_requests"
        " (timestamp, capt_node_id, src_mac, dst_port, dst_ip, flags, http_host"
        ", cookie_domain, search_queries)"
        " VALUES"
        " (timestamptz 'epoch' + $1 * interval '1 second', $2, $3, $4, $5, $6"
        ", $7, $8, $9);");

    String ts_str = ts.unparse();
    String node_id_str = String(node_id);
    String src_str = src.unparse_colon();
    String dst_ip_str = dst_ip.unparse();
    String dst_port_str = String((uint32_t)dst_port);
    String flags_str = String((uint32_t)flags);

    values.push_back(ts_str.c_str());
    values.push_back(node_id_str.c_str());
    values.push_back(src_str.c_str());
    values.push_back(dst_port_str.c_str());
    values.push_back(dst_ip_str.c_str());
    values.push_back(flags_str.c_str());
    values.push_back((strlen(http_host) > 0) ? http_host : NULL);
    values.push_back((strlen(cookie_domain) > 0) ? cookie_domain : NULL);
    values.push_back((strlen(search_queries) > 0) ? search_queries : NULL);

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0)
        _log->error("db_insert failed: %s", errh.get_last_error().c_str());
    else if (rv == 1)
        _log->debug("1 row inserted for src %d, node_id %d", src_str.c_str(),
            node_id);
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for src %s, node_id %d", rv,
            src_str.c_str(), node_id);
}

bool
WebRequestTracker::get_mac_addrs(const Packet *p, EtherAddress *src, EtherAddress *dst)
{
    if (!p->has_mac_header()) {
        _log->error("packet received with no mac header marked");
        return false;
    }
    size_t len_from_mac = p->length() - p->mac_header_offset();

    if (_dlt == DLT_EN10MB) {
        if (len_from_mac < sizeof(struct click_ether)) {
            // should not happen in practice
            _log->error("packet too short to read mac header (%d bytes)", len_from_mac);
            return false;
        }
        const struct click_ether *ether = p->ether_header();
        *src = EtherAddress(ether->ether_shost);
        *dst = EtherAddress(ether->ether_dhost);
        return true;
    }
    else if ((_dlt == DLT_IEEE802_11) || (_dlt == DLT_IEEE802_11_RADIO)) {
        const u_char *sa = NULL, *ta = NULL, *da = NULL, *ra = NULL, *ba = NULL;
        int rv = wifi_extract_addrs(p->data(), p->length(), &sa, &ta, &da, &ra, &ba);

        // many of these errors should not happen in practice since we (should)
        // only receive verified IP packets - hence chatty error messages

        if (rv == -1) {
            // bad frame
            _log->error("invalid wifi frame header");
            return false;
        }

        if (rv == 0) {
            // frame truncated
            _log->warning("wifi frame header truncated (%d bytes)", len_from_mac);
            return false;
        }

        if ((sa == NULL) || (da == NULL)) {
            // either src address or dst address missing
            if (sa != NULL)
                _log->error("wifi frame header missing dst address");
            else if (da != NULL)
                _log->error("wifi frame header missing src address");
            else
                _log->error("wifi frame header missing src and dst addresses");
            return false;
        }

        *src = EtherAddress(sa);
        *dst = EtherAddress(da);
        return true;
    }
    else {
        // configure should have rejected this DLT value - this method and
        // configure() must be out of sync...
        assert(0  /* invalid dlt value */);
        return false;
    }
}
struct http_request *
WebRequestTracker::http_parse(Packet *p)
{
    if (!p->has_transport_header()) {
        _log->error("no transport-header pointer in packet");
        return NULL;
    }

    const struct click_tcp *tcp = p->tcp_header();
    const uint8_t *tcp_data = p->transport_header() + tcp->th_off*4;
    if (tcp_data > p->end_data())
        return NULL;

    size_t tcp_data_len = p->end_data() - tcp_data;
    return pktparse_parse_http_request((char*)tcp_data, tcp_data_len);
}

void
WebRequestTracker::process_packet(IPFlowID *id, TCPFlowInfo *info, Packet *p,
    bool request_stream)
{
    if (p->timestamp_anno() < info->_min_ts) info->_min_ts = p->timestamp_anno();
    if (p->timestamp_anno() > info->_max_ts) info->_max_ts = p->timestamp_anno();

    if (request_stream && ((info->_flags & ARGOS_WEBREQ_F_REQUEST) == 0)) {
        info->_flags |= ARGOS_WEBREQ_F_REQUEST;
        _log->debug("Request flag enabled for %s", id->unparse().c_str());
    }
    else if ((info->_flags & ARGOS_WEBREQ_F_RESPONSE) == 0) {
        info->_flags |= ARGOS_WEBREQ_F_RESPONSE;
        _log->debug("Response flag enabled for %s", id->unparse().c_str());
    }

    const struct click_ip *ip_hdr = p->ip_header();
    const struct click_tcp *tcp_hdr = p->tcp_header();
    uint32_t payload_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4 -
        tcp_hdr->th_off*4;

    if (request_stream) {
        uint32_t seqnum = ntohl(tcp_hdr->th_seq);

        if (!(info->_flags & ARGOS_WEBREQ_F_REQSYN) && (tcp_hdr->th_flags & TH_SYN)) {
            // if we haven't yet seen a SYN and this packet has a SYN....
            info->_flags |= ARGOS_WEBREQ_F_REQSYN;
            info->_syn_seq = seqnum;
            _log->debug("ReqSYN flag enabled for %s", id->unparse().c_str());

            // record if we (previously) captured the segment right after the
            // SYN (but didn't know, since we hadn't seen the SYN packet)
            if (info->_has_data && (info->_min_data_seq = (info->_syn_seq + 1))) {
                info->_flags |= ARGOS_WEBREQ_F_REQHEAD;
                _log->debug("ReqHead flag back-enabled for %s", id->unparse().c_str());
            }
        }

        // no data in packet?  we are done with it
        if (payload_len == 0) return;

        // if we know the SYN sequence number but haven't yet captured the first
        // data segment then check if this current packet is that first segment
        if (!(info->_flags & ARGOS_WEBREQ_F_REQHEAD) && (info->_flags & ARGOS_WEBREQ_F_REQSYN)) {
            if (seqnum == (info->_syn_seq+1)) {
                info->_flags |= ARGOS_WEBREQ_F_REQHEAD;
                _log->debug("ReqHead flag enabled for %s", id->unparse().c_str());
            }
        }

        // check if this is the lowest sequence numbered data segment yet seen
        if (!info->_has_data || SEQ_LT(seqnum, info->_min_data_seq)) {
            info->_has_data = true;
            info->_min_data_seq = seqnum;
        }

        // Try to parse an HTTP header out of this segment; note that if this
        // isn't the first data segment there is a possibility of a false
        // positive (imagine someone requesting a web page whose content is the
        // text of an http request).  However this is low probability especially
        // since we only search at segment boundaries (but we probably don't
        // lose much by doing this since multiple HTTP requests in a single tcp
        // stream are likely to appear only at segment boundaries).
        struct http_request *req = http_parse(p);
        if (req != NULL) {
            // if we haven't found a Host field yet, but did this time, save it
            if ((info->_http_host == NULL) && (req->host != NULL)) {
                info->_http_host = strndup(req->host, 256);
                info->_flags |= ARGOS_WEBREQ_F_HTTPHOST;
                _log->debug("HttpHost flag enabled for %s", id->unparse().c_str());

                // hostnames can end in ':PORT' - trim that off if so
                char *colon = strchr(info->_http_host, ':');
                if (colon != NULL)
                    colon[0] = '\0';
            }

            // also look in the requested resource for anything that looks like
            // a web search query

            // yahoo.com seems to use 'p=XXX' for searches but most/all
            // other big players use 'q=XXX' (google, bing, ask.com, aol)
            const char *key = "q=";
            if ((req->host != NULL) && (strstr(req->host, "yahoo.com") != NULL))
                key = "p=";

            char *end = strchr(req->resource, '?');
            while (end != NULL) {
                char *start = end + 1;
                if (*start == '\0') break;

                size_t term_len;
                end = strchr(start, '&');
                if (end == NULL)
                    term_len = strlen(start);
                else
                    term_len = end - start;

                if ((term_len >= 3) && (strncmp(start, key, strlen(key)) == 0)) {
                    char *query = strndup(start, term_len);

                    _log->debug("search query found for %s: %s",
                        id->unparse().c_str(), query);

                    // whenever allocating memory, allocate in at least 1024
                    // byte blocks for efficiency
                    size_t memreq;
                    if (info->_search_queries == NULL) {
                        memreq = (1024 > term_len) ? 1024 : (term_len+1);
                        info->_search_queries = (char*)malloc(memreq);
                        if (info->_search_queries == NULL) {
                            _log->error("malloc(%u) failed: %s", memreq,
                                strerror(errno));
                        } else {
                            info->_search_queries_alloc = memreq;
                            snprintf(info->_search_queries, memreq, "%s", query);
                        }

                        // try to avoid recording duplicates
                    } else if (strstr(info->_search_queries, query) != NULL) {
                        _log->debug("skipping duplicate query for %s",
                            id->unparse().c_str());
                    } else {
                        size_t curlen = strlen(info->_search_queries);
                        memreq = curlen + 1 + term_len + 1;
                        if (memreq < (curlen + 1024)) memreq = curlen + 1024;
                        
                        char *newbuf = (char*)realloc(info->_search_queries, memreq);
                        if (newbuf == NULL) {
                            _log->error("realloc(%u) failed: %s", memreq,
                                strerror(errno));
                        } else {
                            info->_search_queries = newbuf;
                            info->_search_queries_alloc = memreq;
                            assert(info->_search_queries[curlen] == '\0');  // todo
                            info->_search_queries[curlen] = '&';
                            info->_search_queries[curlen+1] = '\0';
                            strlcat(info->_search_queries, query, memreq);
                        }

                        _log->debug("search queries list for %s is now: %s",
                            id->unparse().c_str(), info->_search_queries);
                    }

                    free(query);

                    break;
                }
            }

            free(req);
        }
        // else, we failed to parse an HTTP request - this can happen
        // normally, so no errors (although its odd if it happens in the
        // first data segment)
    } else {
        // !request_stream  (hence, its the response stream)
        
        // no data in packet?  we are done with it
        if (payload_len == 0) return;

        // try to parse this data segment as an HTTP response
        int32_t remaining = payload_len;
        const char *payload = (const char*)(p->transport_header() + tcp_hdr->th_off*4);
        const char *eol = strnstr(payload, "\r\n", remaining);
        if (eol == NULL) return;
        size_t len = eol - payload;
        const char *key = "HTTP/1";
        size_t keylen = strlen(key);

        if (len < keylen) return;

        if (strncmp(payload, key, keylen) != 0)
            // does not look like an HTTP response
            return;

        const char *cp = eol + 2;
        remaining -= (len + 2);

        while (remaining > 0) {
            const char *eol = strnstr(cp, "\r\n", remaining);
            if (eol == NULL) return;
            size_t len = eol - cp;
            const char *key = "Set-Cookie: ";
            size_t keylen = strlen(key);

            if ((len >= keylen) && (strncmp(cp, key, keylen) == 0)) {
                // there is no strncasestr, so try a few options (I have seen at
                // least 'domain' and 'Domain' in actual usage)
                const char *domain = strnstr(cp, "domain=", len);
                if (domain == NULL) domain = strnstr(cp, "Domain=", len);
                if (domain == NULL) domain = strnstr(cp, "DOMAIN=", len);

                if (domain != NULL) {
                    // found a domain!  Skip over to the value itself
                    domain += strlen("domain=");

                    // if the domain start with a '.', skip that
                    if (domain[0] == '.') domain++;

                    // find the end of the domain field
                    size_t domlen = strcspn(domain, " ;,\r\n");

                    assert((ssize_t)domlen <= (eol - domain));

                    if (info->_cookie_domain == NULL)
                        _log->debug("CookieDomain flag enabled for %s", id->unparse().c_str());

                    // if we have previously parsed a set-cookie domain, then
                    // keep whichever is *longer* (because presumably that one
                    // will be more specific wrt which site sent the response)
                    if ((info->_cookie_domain != NULL) && (domlen > strlen(info->_cookie_domain))) {
                        free(info->_cookie_domain);
                        info->_cookie_domain = NULL;
                    }

                    if (info->_cookie_domain == NULL) {
                        info->_cookie_domain = strndup(domain, domlen);
                        info->_flags |= ARGOS_WEBREQ_F_COOKIEDOM;
                    }
                }
            }
            cp = eol + 2;
            remaining -= (len + 2);
        }
    }
}

void
WebRequestTracker::send_message(const IPFlowID &id, const TCPFlowInfo &info)
{
    assert(!info._terminated);

    size_t reqlen = sizeof(struct argos_userweb_msg) + 1 +
        (info._search_queries == NULL ? 0 : strlen(info._search_queries));
    WritablePacket *p;
    try {
        p = Packet::make(0, NULL, reqlen, 0);
    }
    catch (std::bad_alloc &ex) {
        _log->error("Packet::make failed for len %d", reqlen);
        return;
    }

    struct argos_userweb_msg *msg = (struct argos_userweb_msg*)p->data();
    bzero(msg, reqlen);
    msg->magic = htonl(ARGOS_WEBREQ_MSG_MAGIC);
    msg->node_id = htonl(info._sniffer_id);
    memcpy(msg->src_mac, info._src_mac.data(), 6);
    msg->dst_port = id.dport();  // note: leave in network byte-order
    msg->dst_ip = id.daddr();    // note: leave in network byte-order
    msg->flags = info._flags;
    msg->first_pkt_sec = htonl((uint32_t)(info._min_ts.sec()));
    msg->first_pkt_usec = htonl(info._min_ts.usec());
    msg->last_pkt_sec = htonl((uint32_t)(info._max_ts.sec()));
    msg->last_pkt_usec = htonl(info._max_ts.usec());

    if (info._http_host != NULL)
        strlcpy(msg->http_host, info._http_host, sizeof(msg->http_host));

    if (info._cookie_domain != NULL)
        strlcpy(msg->cookie_domain, info._cookie_domain, sizeof(msg->cookie_domain));

    if (info._search_queries != NULL)
        strcpy(msg->search_queries, info._search_queries);

    output(0).push(p);
}

// Static methods

String
WebRequestTracker::read_handler(Element *e, void *thunk)
{
    const WebRequestTracker *elt = static_cast<WebRequestTracker *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    StringAccum sa;

    switch (which) {
    case H_MEM_USED:
        return String(elt->_mem_used);
    case H_ACTIVE_SESSIONS:
        return String(elt->_sessions.size());
    default:
        return "internal error (bad thunk value)";
    }
}

int
WebRequestTracker::write_handler(const String &, Element *e, void *thunk,
    ErrorHandler *errh)
{
    WebRequestTracker *elt = static_cast<WebRequestTracker *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_TIMEOUT_ALL:
        return elt->timeout_all_sessions();
    default:
        return errh->error("internal error (bad thunk value)");
    }
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(WebRequestTracker)
// hard-coded paths suck, but I don't know how else to do this.
// "-rpath=$HOME/lib" doesn't work because gmake parses it wrong, and
// "-rpath=$(HOME)/lib" doesn't work because click-buildtool gets confused by
// the parentheses
ELEMENT_LIBS(-L=~/lib -rpath=/usr/home/ianrose/lib -lpktparse)
