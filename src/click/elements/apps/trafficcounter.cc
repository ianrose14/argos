/*
 * trafficcounter.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "trafficcounter.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <unistd.h>
#include <sys/endian.h>  /* for be64toh and htobe64 which may not be portable */
#include <pcap/pcap.h>
#include "../pktparse_wrap.hh"
#include "../loghandler.hh"
#include "../nodeinfo.hh"
#include "../wifiutil.hh"
CLICK_DECLS

/*
 * STATIC DATA
 */

static const String raw_ether_query = String("INSERT INTO ether_traffic_types"
    " (ethertype_id, capt_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, timestamptz 'epoch' + $3 * interval '1 second', $4, $5, $6);");

static const String agg_ether_query = String("INSERT INTO ether_traffic_types"
    " (ethertype_id, agg_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, timestamptz 'epoch' + $3 * interval '1 second', $4, $5, $6);");

static const String raw_wifi_query = String("INSERT INTO wifi_traffic_types"
    " (type_id, subtype_id, capt_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, $3, timestamptz 'epoch' + $4 * interval '1 second', $5, $6, $7);");

static const String agg_wifi_query = String("INSERT INTO wifi_traffic_types"
    " (type_id, subtype_id, agg_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, $3, timestamptz 'epoch' + $4 * interval '1 second', $5, $6, $7);");

static const String raw_ip_query = String("INSERT INTO ipproto_traffic_types"
    " (ipproto_id, capt_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, timestamptz 'epoch' + $3 * interval '1 second', $4, $5, $6);");

static const String agg_ip_query = String("INSERT INTO ipproto_traffic_types"
    " (ipproto_id, agg_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, timestamptz 'epoch' + $3 * interval '1 second', $4, $5, $6);");

static const String raw_tcp_query = String("INSERT INTO tcp_traffic_types"
    " (low_port, high_port, capt_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, $3, timestamptz 'epoch' + $4 * interval '1 second', $5, $6, $7);");

static const String agg_tcp_query = String("INSERT INTO tcp_traffic_types"
    " (low_port, high_port, agg_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, $3, timestamptz 'epoch' + $4 * interval '1 second', $5, $6, $7);");

static const String raw_udp_query = String("INSERT INTO udp_traffic_types"
    " (low_port, high_port, capt_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, $3, timestamptz 'epoch' + $4 * interval '1 second', $5, $6, $7);");

static const String agg_udp_query = String("INSERT INTO udp_traffic_types"
    " (low_port, high_port, agg_node_id, timestamp, duration_sec, packets, bytes)"
    " VALUES ($1, $2, $3, timestamptz 'epoch' + $4 * interval '1 second', $5, $6, $7);");

/*
 * Public Methods
 */

TrafficCounter::TrafficCounter()
    : _am_server(false), _node_id(0), _merged(false), _timer(this),
      _interval(15*60), _dlt(-1), _ether_enabled(true), _wifi_enabled(true),
      _ip_enabled(true), _tcp_enabled(true), _udp_enabled(true), _db(NULL),
      _log(NULL)
{
}

TrafficCounter::~TrafficCounter()
{
}

enum { H_SEND_NOW };

void
TrafficCounter::add_handlers()
{
    if (!_am_server) {
        add_write_handler("send_now", write_handler, (void*)H_SEND_NOW);
    }
}

int
TrafficCounter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dlt_name = "EN10MB";
    String tcp_portstr, udp_portstr;
    bool has_node_id, has_merged, has_tcp_ports, has_udp_ports;
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "NODE_ID", cpkC, &has_node_id, cpInteger, &_node_id,
            "MERGED", cpkC, &has_merged, cpBool, &_merged,
            "ETHER", 0, cpBool, &_ether_enabled,
            "WIFI", 0, cpBool, &_wifi_enabled,
            "IP", 0, cpBool, &_ip_enabled,
            "TCP", 0, cpBool, &_tcp_enabled,
            "UDP", 0, cpBool, &_udp_enabled,
            "TCP_PORTS", cpkC, &has_tcp_ports, cpArgument, &tcp_portstr,
            "UDP_PORTS", cpkC, &has_udp_ports, cpArgument, &udp_portstr,
            "DLT", 0, cpString, &dlt_name,
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

    _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
    if (_dlt < 0)
        return errh->error("bad datalink type");

    if (_am_server) {
        if (has_node_id)
            return errh->error("NODE_ID parameter is meaningless when SERVER=true");

        if (has_merged)
            return errh->error("MERGED parameter is meaningless when SERVER=true");

        if (has_tcp_ports)
            return errh->error("TCP_PORTS parameter is meaningless when SERVER=true");

        if (has_udp_ports)
            return errh->error("UDP_PORTS parameter is meaningless when SERVER=true");

        if (noutputs() != 0)
            return errh->error("when SERVER=true, element does not support outputs");
    }
    else {
        if (noutputs() != 2)
            return errh->error("when SERVER=false, element must have exactly 2 outputs");

        if (_tcp_enabled && !has_tcp_ports)
            return errh->error("TCP_PORTS parameter is required when TCP tracking is enabled");

        if (_udp_enabled && !has_udp_ports)
            return errh->error("UDP_PORTS parameter is required when UDP tracking is enabled");

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

        // parse tcp/udp port strings
        tcp_portstr = cp_unquote(tcp_portstr);

        Vector<String> parts;
        cp_spacevec(tcp_portstr, parts);
        if (parts.size() == 0)
            return errh->error("no TCP ports specified");

        for (int i=0; i < parts.size(); i++) {
            uint16_t low_port, high_port;
            if (!parse_port_pair(parts[i], &low_port, &high_port))
                return errh->error("expected PORT or PORT-PORT, not '%s'",
                    parts[i].c_str());

            _tcp_low_ports.push_back(low_port);
            _tcp_high_ports.push_back(high_port);
            _tcp_counts.push_back(PktCounter());
        }

        udp_portstr = cp_unquote(udp_portstr);

        parts.clear();
        cp_spacevec(udp_portstr, parts);
        if (parts.size() == 0)
            return errh->error("no UDP ports specified");

        for (int i=0; i < parts.size(); i++) {
            uint16_t low_port, high_port;
            if (!parse_port_pair(parts[i], &low_port, &high_port))
                return errh->error("expected PORT or PORT-PORT, not '%s'",
                    parts[i].c_str());

            _udp_low_ports.push_back(low_port);
            _udp_high_ports.push_back(high_port);
            _udp_counts.push_back(PktCounter());
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
TrafficCounter::initialize(ErrorHandler *)
{
    if (!_am_server) {
        _timer.initialize(this);
        _timer.schedule_after(_interval);
        _interval_start = Timestamp::now();
    }
    return 0;
}

void
TrafficCounter::run_timer(Timer *)
{
    Timestamp now = Timestamp::now();
    Timestamp started = _interval_start;
    Timestamp elapsed = now - _interval_start;
    _timer.reschedule_after(_interval);
    _interval_start = now;

    //
    // Ether Counts
    //
    uint32_t nrecords = _ether_counts.size();
    if (nrecords > 0) {
        size_t reqlen = sizeof(struct argos_trafficcount_header) +
            nrecords*sizeof(struct argos_trafficcount_record);

        WritablePacket *p;
        try {
            p = Packet::make(0, NULL, reqlen, 0);
        }
        catch (std::bad_alloc &ex) {
            _log->error("Packet::make failed for len %d", reqlen);
            return;
        }

        _log->debug("allocated %u byte packet", reqlen);
        struct argos_trafficcount_header *hdr = (struct argos_trafficcount_header*)p->data();
        hdr->magic = htonl(TRAFFICCOUNTER_MAGIC);
        hdr->node_id = htonl(_node_id);
        hdr->is_merged = (_merged ? 1 : 0);
        hdr->traffic_class = (uint8_t)TRAFFIC_CLASS_ETHER;
        hdr->ts_sec = htonl(started.sec());
        hdr->duration_sec = htonl(elapsed.sec());
        hdr->num_records = htonl(nrecords);
        
        struct argos_trafficcount_record *records = (struct argos_trafficcount_record*)
            (p->data() + sizeof(struct argos_trafficcount_header));

        HashMap<uint16_t, PktCounter>::const_iterator iter = _ether_counts.begin();
        uint32_t i=0;
        for (; iter != _ether_counts.end(); iter++) {
            assert(i < nrecords);
            records[i].type = htonl(iter.key());
            // records[i].subtype is unused
            records[i].packets = htobe64(iter.value().pkt_count);
            records[i].bytes = htobe64(iter.value().byte_count);
            i++;
        }
        assert(i == nrecords);

        output(1).push(p);
        _ether_counts.clear();
    }

    //
    // Wifi Counts
    //

    // first count all of the non-zero entries
    nrecords = 0;
    for (int i=0; i < 64; i++) {
        if (_wifi_counts[i].pkt_count > 0) nrecords++;
    }

    if (nrecords > 0) {
        // now we know how big of a packet we will need
        size_t reqlen = sizeof(struct argos_trafficcount_header) +
            nrecords*sizeof(struct argos_trafficcount_record);

        WritablePacket *p;
        try {
            p = Packet::make(0, NULL, reqlen, 0);
        }
        catch (std::bad_alloc &ex) {
            _log->error("Packet::make failed for len %d", reqlen);
            return;
        }

        _log->debug("allocated %u byte packet", reqlen);
        struct argos_trafficcount_header *hdr = (struct argos_trafficcount_header*)p->data();
        hdr->magic = htonl(TRAFFICCOUNTER_MAGIC);
        hdr->node_id = htonl(_node_id);
        hdr->is_merged = (_merged ? 1 : 0);
        hdr->traffic_class = (uint8_t)TRAFFIC_CLASS_WIFI;
        hdr->ts_sec = htonl(started.sec());
        hdr->duration_sec = htonl(elapsed.sec());
        hdr->num_records = htonl(nrecords);
    
        struct argos_trafficcount_record *records = (struct argos_trafficcount_record*)
            (p->data() + sizeof(struct argos_trafficcount_header));

        uint32_t i=0;
        for (uint32_t index=0; index < 64; index++) {
            if (_wifi_counts[index].pkt_count > 0) {
                assert(i < nrecords);
                records[i].type = htonl(index & 0x3);   // low 2 bytes = type
                records[i].subtype = htonl(index >> 2);  // high 4 bytes = subtype
                records[i].packets = htobe64(_wifi_counts[index].pkt_count);
                records[i].bytes = htobe64(_wifi_counts[index].byte_count);
                _wifi_counts[index].reset();
                i++;
            }
        }
        assert(i == nrecords);

        output(1).push(p);
    }

    //
    // IP Counts
    //
    nrecords = _ip_counts.size();
    if (nrecords > 0) {
        // now we know how big of a packet we will need
        size_t reqlen = sizeof(struct argos_trafficcount_header) +
            nrecords*sizeof(struct argos_trafficcount_record);

        WritablePacket *p;
        try {
            p = Packet::make(0, NULL, reqlen, 0);
        }
        catch (std::bad_alloc &ex) {
            _log->error("Packet::make failed for len %d", reqlen);
            return;
        }

        _log->debug("allocated %u byte packet", reqlen);
        struct argos_trafficcount_header *hdr = (struct argos_trafficcount_header*)p->data();
        hdr->magic = htonl(TRAFFICCOUNTER_MAGIC);
        hdr->node_id = htonl(_node_id);
        hdr->is_merged = (_merged ? 1 : 0);
        hdr->traffic_class = (uint8_t)TRAFFIC_CLASS_IP;
        hdr->ts_sec = htonl(started.sec());
        hdr->duration_sec = htonl(elapsed.sec());
        hdr->num_records = htonl(nrecords);
    
        struct argos_trafficcount_record *records = (struct argos_trafficcount_record*)
            (p->data() + sizeof(struct argos_trafficcount_header));

        HashMap<uint8_t, PktCounter>::const_iterator iter = _ip_counts.begin();
        uint32_t i=0;
        for (; iter != _ip_counts.end(); iter++) {
            assert(i < nrecords);
            records[i].type = htonl(iter.key());
            // records[i].subtype is unused
            records[i].packets = htobe64(iter.value().pkt_count);
            records[i].bytes = htobe64(iter.value().byte_count);
            i++;
        }
        assert(i == nrecords);

        output(1).push(p);
        _ip_counts.clear();
    }

    //
    // TCP Counts
    //

    // first count all of the non-zero entries
    nrecords = 0;
    for (int i=0; i < _tcp_counts.size(); i++) {
        if (_tcp_counts[i].pkt_count > 0) nrecords++;
    }

    if (nrecords > 0) {
        // now we know how big of a packet we will need
        size_t reqlen = sizeof(struct argos_trafficcount_header) +
            nrecords*sizeof(struct argos_trafficcount_record);

        WritablePacket *p;
        try {
            p = Packet::make(0, NULL, reqlen, 0);
        }
        catch (std::bad_alloc &ex) {
            _log->error("Packet::make failed for len %d", reqlen);
            return;
        }

        _log->debug("allocated %u byte packet", reqlen);
        struct argos_trafficcount_header *hdr = (struct argos_trafficcount_header*)p->data();
        hdr->magic = htonl(TRAFFICCOUNTER_MAGIC);
        hdr->node_id = htonl(_node_id);
        hdr->is_merged = (_merged ? 1 : 0);
        hdr->traffic_class = (uint8_t)TRAFFIC_CLASS_TCP;
        hdr->ts_sec = htonl(started.sec());
        hdr->duration_sec = htonl(elapsed.sec());
        hdr->num_records = htonl(nrecords);
    
        struct argos_trafficcount_record *records = (struct argos_trafficcount_record*)
            (p->data() + sizeof(struct argos_trafficcount_header));

        uint32_t i=0;
        for (int index=0; index < _tcp_counts.size(); index++) {
            if (_tcp_counts[index].pkt_count > 0) {
                assert(i < nrecords);
                records[i].type = htonl(_tcp_low_ports[index]);
                records[i].subtype = htonl(_tcp_high_ports[index]);
                records[i].packets = htobe64(_tcp_counts[index].pkt_count);
                records[i].bytes = htobe64(_tcp_counts[index].byte_count);
                _tcp_counts[index].reset();
                i++;
            }
        }
        assert(i == nrecords);

        output(1).push(p);
    }

    //
    // UDP Counts
    //

    // first count all of the non-zero entries
    nrecords = 0;
    for (int i=0; i < _udp_counts.size(); i++) {
        if (_udp_counts[i].pkt_count > 0) nrecords++;
    }

    if (nrecords > 0) {
        // now we know how big of a packet we will need
        size_t reqlen = sizeof(struct argos_trafficcount_header) +
            nrecords*sizeof(struct argos_trafficcount_record);

        WritablePacket *p;
        try {
            p = Packet::make(0, NULL, reqlen, 0);
        }
        catch (std::bad_alloc &ex) {
            _log->error("Packet::make failed for len %d", reqlen);
            return;
        }

        _log->debug("allocated %u byte packet", reqlen);
        struct argos_trafficcount_header *hdr = (struct argos_trafficcount_header*)p->data();
        hdr->magic = htonl(TRAFFICCOUNTER_MAGIC);
        hdr->node_id = htonl(_node_id);
        hdr->is_merged = (_merged ? 1 : 0);
        hdr->traffic_class = (uint8_t)TRAFFIC_CLASS_UDP;
        hdr->ts_sec = htonl(started.sec());
        hdr->duration_sec = htonl(elapsed.sec());
        hdr->num_records = htonl(nrecords);
    
        struct argos_trafficcount_record *records = (struct argos_trafficcount_record*)
            (p->data() + sizeof(struct argos_trafficcount_header));

        uint32_t i=0;
        for (int index=0; index < _udp_counts.size(); index++) {
            if (_udp_counts[index].pkt_count > 0) {
                assert(i < nrecords);
                records[i].type = htonl(_udp_low_ports[index]);
                records[i].subtype = htonl(_udp_high_ports[index]);
                records[i].packets = htobe64(_udp_counts[index].pkt_count);
                records[i].bytes = htobe64(_udp_counts[index].byte_count);
                _udp_counts[index].reset();
                i++;
            }
        }
        assert(i == nrecords);

        output(1).push(p);
    }
}

Packet *
TrafficCounter::simple_action(Packet *p)
{
    if (_am_server) {
        struct argos_trafficcount_header *hdr = (struct argos_trafficcount_header*)p->data();
        if (p->length() < sizeof(struct argos_trafficcount_header)) {
            _log->error("bad message received with length=%d and misc-ip=%s",
                p->length(), IPAddress(MISC_IP_ANNO(p)).unparse().c_str());
            p->kill();
            return NULL;
        }

        if (ntohl(hdr->magic) != TRAFFICCOUNTER_MAGIC) {
            _log->error("bad message received with magic=0x%08x and misc-ip=%s",
                ntohl(hdr->magic), IPAddress(MISC_IP_ANNO(p)).unparse().c_str());
            p->kill();
            return NULL;
        }

        int32_t node_id = ntohl(hdr->node_id);
        bool is_merged = hdr->is_merged;
        uint8_t traffic_class = hdr->traffic_class;
        uint32_t ts_sec = ntohl(hdr->ts_sec);
        uint32_t duration_sec = ntohl(hdr->duration_sec);
        uint32_t nrecords = ntohl(hdr->num_records);

        uint32_t reqlen = sizeof(struct argos_trafficcount_header) +
            nrecords*sizeof(struct argos_trafficcount_record);

        if (p->length() < reqlen) {
            _log->error("bad message received with nrecs=%u but len=%u (expected %u)",
                nrecords, p->length(), reqlen);
            p->kill();
            return NULL;
        }

        if (p->length() > reqlen)
            _log->warning("oversized message received with nrecs=%u but len=%u (expected %u)",
                nrecords, p->length(), reqlen);

        struct argos_trafficcount_record *records = (struct argos_trafficcount_record*)
            (p->data() + sizeof(struct argos_trafficcount_header));

        for (uint32_t i=0; i < nrecords; i++) {
            uint32_t type = ntohl(records[i].type);
            uint32_t subtype = ntohl(records[i].subtype);
            uint64_t packets = be64toh(records[i].packets);
            uint64_t bytes = be64toh(records[i].bytes);

            // insert data into database (if we have a db handle)
            if (_db) db_insert(traffic_class, type, subtype, node_id, is_merged,
                ts_sec, duration_sec, packets, bytes);

            String tc = traffic_class_desc(traffic_class);
            _log->data("%llu packets reported by node %d (%s) for %s type 0x%02X subtype 0x%04X",
                packets, node_id, (is_merged ? "merged" : "raw"), tc.c_str(), type, subtype);
        }

        // done!
        p->kill();
        return NULL;
    } else {
        // !_am_server

        struct packet pkt;
        if (pktparse_click_packet(p, _dlt, &pkt) < 0) {
            _log->warning("pktparse_parse: %s", pkt.errmsg);
        } else {
            // increment counts for ethertype if there is one
            if (_ether_enabled && (pkt.ethertype != -1)) {
                PktCounter *pc = _ether_counts.findp(pkt.ethertype);
                if (pc == NULL)
                    _ether_counts.insert(pkt.ethertype, PktCounter(1, p->length()));
                else {
                    pc->incr(p);
                }
            }

            if (_wifi_enabled && (pkt.wifi_hdr != NULL)) {
                uint8_t type_subtype = pkt.wifi_hdr->i_fc[0] >> 2;
                assert(type_subtype < 64);
                _wifi_counts[type_subtype].incr(p);
            }

            if (_ip_enabled && (pkt.ip_hdr != NULL)) {
                uint8_t ipproto = pkt.ip_hdr->ip_p;
                PktCounter *pc = _ip_counts.findp(ipproto);
                if (pc == NULL)
                    _ip_counts.insert(ipproto, PktCounter(1, p->length()));
                else
                    pc->incr(1, ntohs(pkt.ip_hdr->ip_len));
            }

            if (_tcp_enabled && (pkt.ip_hdr != NULL) && (pkt.tcp_hdr != NULL)) {
                uint16_t sport = ntohs(pkt.tcp_hdr->th_sport);
                uint16_t dport = ntohs(pkt.tcp_hdr->th_dport);
                uint32_t tcplen = ntohs(pkt.ip_hdr->ip_len) - pkt.ip_hdr->ip_hl*4;

                for (int i=0; i < _tcp_low_ports.size(); i++) {
                    if (((sport >= _tcp_low_ports[i]) && (sport <= _tcp_high_ports[i])) ||
                        ((dport >= _tcp_low_ports[i]) && (dport <= _tcp_high_ports[i]))) {
                        _tcp_counts[i].incr(1, tcplen);
                    }
                }
            }

            if (_udp_enabled && (pkt.ip_hdr != NULL) && (pkt.udp_hdr != NULL)) {
                uint16_t sport = ntohs(pkt.udp_hdr->uh_sport);
                uint16_t dport = ntohs(pkt.udp_hdr->uh_dport);
                uint32_t udplen = ntohs(pkt.ip_hdr->ip_len) - pkt.ip_hdr->ip_hl*4;

                for (int i=0; i < _udp_low_ports.size(); i++) {
                    if (((sport >= _udp_low_ports[i]) && (sport <= _udp_high_ports[i])) ||
                        ((dport >= _udp_low_ports[i]) && (dport <= _udp_high_ports[i]))) {
                        _udp_counts[i].incr(1, udplen);
                    }
                }
            }
        }

        return p;
    }
}

void
TrafficCounter::db_insert(uint8_t traffic_class, uint32_t type, uint32_t subtype,
    int32_t node_id, bool merged, uint32_t ts_sec, uint32_t duration_sec,
    uint64_t packets, uint64_t bytes)
{
    // not all traffic classes use the subtype field
    String query;
    bool use_subtype_field = false;

    switch (traffic_class) {
    case TRAFFIC_CLASS_ETHER:
        query = merged ? agg_ether_query : raw_ether_query;
        break;
    case TRAFFIC_CLASS_WIFI:
        use_subtype_field = true;
        query = merged ? agg_wifi_query : raw_wifi_query;
        break;
    case TRAFFIC_CLASS_IP:
        query = merged ? agg_ip_query : raw_ip_query;
        break;
    case TRAFFIC_CLASS_TCP:
        use_subtype_field = true;
        query = merged ? agg_tcp_query : raw_tcp_query;
        break;
    case TRAFFIC_CLASS_UDP:
        use_subtype_field = true;
        query = merged ? agg_udp_query : raw_udp_query;
        break;
    default:
        _log->error("unknown traffic class (%d) in db_insert", traffic_class);
        return;
    }

    String type_str = String(type);
    String subtype_str = String(subtype);
    String node_id_str = String(node_id);
    String ts_sec_str = String(ts_sec);
    String duration_str = String(duration_sec);
    String packets_str = String(packets);
    String bytes_str = String(bytes);

    Vector<const char*> values;
    values.push_back(type_str.c_str());
    if (use_subtype_field) values.push_back(subtype_str.c_str());
    values.push_back(node_id_str.c_str());
    values.push_back(ts_sec_str.c_str());
    values.push_back(duration_str.c_str());
    values.push_back(packets_str.c_str());
    values.push_back(bytes_str.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);

    String tc = traffic_class_desc(traffic_class);

    if (rv < 0) {
        StringAccum sa;
        for (int i=0; i < values.size(); i++)
            sa << String(values[i]) << " | ";
        _log->error("db_insert for %s failed: %s  (args: %s)", tc.c_str(),
            errh.get_last_error().c_str(), sa.take_string().c_str());
    }
    else if (rv == 1) {
        if (use_subtype_field)
            _log->debug("1 row inserted for %s type 0x%02x subtype 0x%04x from node_id %d",
                tc.c_str(), type, subtype, node_id);
        else
            _log->debug("1 row inserted for %s type 0x%02x from node_id %d",
                tc.c_str(), type, node_id);
    } else {
        // should never affect 0 or >1 rows
        if (use_subtype_field)
            _log->error("%d rows inserted for %s type 0x%02x subtype 0x%04x from node_id %d",
                tc.c_str(), type, subtype, node_id);
        else
            _log->error("%d rows inserted for %s type 0x%02x from node_id %d",
                tc.c_str(), type, node_id);
    }
}

bool
TrafficCounter::parse_port_pair(String &s, uint16_t *low, uint16_t *high)
{
    uint8_t ipproto = IP_PROTO_TCP;  // should work for udp too
    int index = s.find_left('-');
    if (index == -1) {
        if (!cp_tcpudp_port(s, ipproto, low, this))
            return false;
        *high = *low;
    } else {
        String a = s.substring(0, index);
        String b = s.substring(index+1);
        if (!cp_tcpudp_port(a, ipproto, low, this))
            return false;
        if (!cp_tcpudp_port(b, ipproto, high, this))
            return false;
    }
    return true;
}

String
TrafficCounter::traffic_class_desc(uint8_t tc)
{
    switch (tc) {
    case TRAFFIC_CLASS_ETHER:
        return  "Ether";
    case TRAFFIC_CLASS_WIFI:
        return "Wifi";
    case TRAFFIC_CLASS_IP:
        return "IP";
    case TRAFFIC_CLASS_TCP:
        return "TCP";
    case TRAFFIC_CLASS_UDP:
        return "UDP";
    default:
        return "?" + String((int)tc) + "?";
    }
}

/*
 * STATIC METHODS
 */

int
TrafficCounter::write_handler(const String&, Element *e, void *thunk,
    ErrorHandler *errh)
{
    TrafficCounter *elt = static_cast<TrafficCounter *>(e);
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
ELEMENT_REQUIRES(PktParse)
EXPORT_ELEMENT(TrafficCounter)
