#!/usr/bin/env python

############################################################
# IMPORTS
############################################################

# system modules
import datetime
import os
import re
import shlex
from subprocess import (Popen, PIPE)
import sys
import time


############################################################
# CONSTANTS
############################################################

DEF_CONFIG_PORT=9605
DEF_QUERY_PRIORITY = 1
TAP_NAMES = [ "raw", "aggregated", "merged", "ip", "tcp" ]

ANNO_OFFSETS={}
ANNO_SIZES={}
SNIFFERS_DLT="IEEE802_11_RADIO"  # the DLT that sniffers are expected to report using

# should be based on estimated number/density of sniffers
PKT_HEADROOM=196   # large enough for a WifiMerge header with 12 elements

# for AdjustTimeSkew element
TIMESKEW_WARMUP=60

# for WifiMerge element
WIFIMERGE_HIMEM=10*1024*1024


############################################################
# CLASSES
############################################################

class ArgosQuery:
    def __init__(self):
        self.name = ""
        self.node_router = ""
        self.server_router = ""
        self.packet_filter = ""
        self.node_taps = []
        self.priority = DEF_QUERY_PRIORITY
        self.queuelen = 100
        self.incl_dupes = True

class ParseError(StandardError):
    pass

############################################################
# METHODS
############################################################

# just like socket.gethostbyname but, on exceptions, decorates the error message
# with the hostname that failed
def gethostbyname(hostname):
    import socket
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror, e:
        e.args = (e.args[0], "%s: %s" % (hostname, e.args[1]))
        raise

def gen_annotation_info():
    lines = []
    puts = lambda line: lines.append(line)
    
    puts("AnnotationInfo(ARGOS_SNIFF %d %d," % (ANNO_OFFSETS["ARGOS_SNIFF"], ANNO_SIZES["ARGOS_SNIFF"]))
    puts("               ARGOS_CTRL %d %d," % (ANNO_OFFSETS["ARGOS_CTRL"], ANNO_SIZES["ARGOS_CTRL"]))
    puts("               TTL %d %d," % (ANNO_OFFSETS["TTL"], ANNO_SIZES["TTL"]))
    puts("               WIFIMERGE %d %d);" % (ANNO_OFFSETS["WIFIMERGE"], ANNO_SIZES["WIFIMERGE"]))
    puts("")
    puts("// Check annotations that can be used by WifiOverlay in captured packets:")
    puts("AnnotationInfo(CHECK_OVERLAP ARGOS_SNIFF TTL WIFI_EXTRA DST_IP PAINT MISC_IP EXTRA_LENGTH);")
    puts("// Check annotations that can be used by WifiOverlay in control messages:")
    puts("AnnotationInfo(CHECK_OVERLAP ARGOS_CTRL TTL DST_IP PAINT MISC_IP EXTRA_LENGTH);")
    puts("// Check annotations that can be used during and after packet merging:")
    puts("AnnotationInfo(CHECK_OVERLAP ARGOS_SNIFF WIFIMERGE WIFI_EXTRA PAINT EXTRA_LENGTH FIRST_TIMESTAMP);")
    puts("// Check annotations that can be used during query-to-server transfers:")
    puts("AnnotationInfo(CHECK_OVERLAP ARGOS_SNIFF WIFIMERGE WIFI_EXTRA PAINT MISC_IP EXTRA_LENGTH PACKET_NUMBER);")
    return "\n".join(lines)

def gen_elementclasses(overlay_queue_capac):
    lines =[]
    puts = lambda line: lines.append(line)

    puts("")
    puts("elementclass PacketError { $src, $msg |")
    puts("    input -> Script(TYPE PACKET,")
    puts("                    set s $(sprintf \"%s on %s\" \"$(msg)\" $(sys.hostname)),")
    puts("                    write loghandler.log $src ERROR \"$(s)\", return 0) -> output;")
    puts("}")
    puts("elementclass WifiOverlayQueue {")
    puts("    input -> in_all::Counter() -> in_sw::PacketTypeSwitch();")
    puts("    // on outgoing packets, hijack dst-IP anno to store our local ip")
    puts("    // address so that receivers will know who sent it")
    puts("    q::Queue(%d) -> SetIPAddress($ARGOS_OVERLAY_IP)" % overlay_queue_capac)
    puts("        -> out_all::Counter()")
    puts("        -> output;")
    puts("    q[1] -> drops_all::Counter() -> drops_sw::PacketTypeSwitch();")
    puts("    // 0 = HOST, 1 = BROADCAST, 2 = MULTICAST, 3 = OTHERHOST, 4 = OUTGOING, 5 = LOOPBACK, 6 = FASTROUTE")
    puts("    in_sw[0] -> in_from_self::Counter() -> q;")
    puts("    in_sw[1] -> in_unknown::Counter() -> q;")
    puts("    in_sw[2] -> in_unknown;")
    puts("    in_sw[3] -> in_from_peers::Counter() -> q;")
    puts("    in_sw[4] -> in_ctrl::Counter() -> q;")
    puts("    in_sw[5] -> in_unknown;")
    puts("    in_sw[6] -> in_unknown;")
    puts("    drops_sw[0] -> drops_from_self::Counter() -> [1]output;")
    puts("    drops_sw[1] -> drops_unknown::Counter() -> [1]output;")
    puts("    drops_sw[2] -> drops_unknown;")
    puts("    drops_sw[3] -> drops_from_peers::Counter() -> [1]output;")
    puts("    drops_sw[4] -> drops_ctrl::Counter() -> [1]output;")
    puts("    drops_sw[5] -> drops_unknown;")
    puts("    drops_sw[6] -> drops_unknown;")
    puts("}")
    puts("elementclass WifiOverlayPath {")
    puts("    input -> all::Counter() -> sw::PacketTypeSwitch();")
    puts("    // 0 = HOST, 1 = BROADCAST, 2 = MULTICAST, 3 = OTHERHOST, 4 = OUTGOING, 5 = LOOPBACK, 6 = FASTROUTE")
    puts("    sw[0] -> from_source::Counter() -> output;")
    puts("    sw[1] -> unknown::Counter() -> output;")
    puts("    sw[2] -> unknown -> output;")
    puts("    sw[3] -> from_reroute::Counter() -> output;")
    puts("    sw[4] -> ctrl::Counter() -> output;")
    puts("    sw[5] -> unknown -> output;")
    puts("    sw[6] -> unknown -> output;")
    puts("}")
    return "\n".join(lines)

def gen_fake_packet_source(loglvls, file_start, real_start, event_start,
                           channel, duration, source, pcap_dir):

    lines = []
    puts = lambda line: lines.append(line)
    
    puts("mch_sim::MultiChannelSim() -> pktsrc::Null();")
    puts("from_pcap::Script(TYPE PROXY, return $(mch_sim.$0));")
    puts("Script(set msg $(sprintf \"capturing from fake traffic on %s\" $(sys.hostname)),")
    puts("    write loghandler.log mch_sim INFO \"$(msg)\");")
    puts("chan_mgr::BasicChannelManager(mch_sim.get_channel, mch_sim.set_channel" + \
         ", LOGGING %s);" % loglvls["chan_mgr"])

    # for all marked packets that were NOT captured (because we were tuned to
    # the wrong channel), remap the duration field from C0C0 to C0C1 so that
    # these packets can be accounted
    puts("mch_sim[1]")
    puts("    -> RadiotapDecap()")
    puts("    -> Classifier(2/C0C0)")
    puts("    -> StoreData(2, 0xC0C1)")
    puts("    -> RadiotapEncap()")
    puts("    -> pktsrc;")
        
    for i in range(1, 12):
        my_file_start = file_start + 300*(i-1)
        ts_offset = real_start - my_file_start
        
        args = ["%s/$(ARGOS_HOSTNAME)_ch%d.pcap" % (pcap_dir, i),
                "TIMING true",
                "MMAP false",
                "START %f" % my_file_start,
                "ACTIVE false",
                "END_CALL s_%d.done" % i]
        puts("from_dump_%d::FromDump(%s) -> " % (i, ", ".join(args)))

        if i == channel:
            assert(event_start <= (my_file_start + 300))
            
            puts("define($ARGOS_FILE_START %f);" % my_file_start)
            puts("define($ARGOS_EVENT_START %f);" % event_start)
            
            args = ["EVENT_ENABLED true",
                    "EVENT_START %f" % event_start,
                    "EVENT_DURATION %d" % duration,
                    "EVENT_SOURCE %s" % source,
                    "EVENT_CHANNEL %d" % channel]
            puts("wes::WifiEventSim(%s) -> " % ", ".join(args))

        puts("AdjustTimestamp(DELTA %f) -> [%d]mch_sim;" % (ts_offset, i-1))
        puts("s_%d::Script(TYPE PROXY, print $(sprintf \"%%s channel %d dumpfile expired\" $(now)));" % \
             (i, i))

    puts("Script(set delay $(sub %f $(now))," % real_start)
    puts("       print $(sprintf \"delay = %s\" $delay),")
    puts("       wait $delay,")
    for i in range(1,12):
        puts("       write from_dump_%d.active true," % i)
    puts("       );")
    return "\n".join(lines)

def gen_inspect_script(queries, nodes):
    lines = []
    puts = lambda line: lines.append(line)
    
    puts("inspect::Script(TYPE PROXY,")
    puts("    goto num_queries $(eq $0 \"num_queries\"),")
    puts("    goto num_nodes $(eq $0 \"num_nodes\"),")
    for i in range(len(queries)):
        puts("    goto query_%d $(eq $0 \"query_%d\")," % (i, i))
    for i in range(len(nodes)):
        puts("    goto host_%d $(eq $0 \"host_%d\")," % (i, i))
        puts("    goto ip_%d $(eq $0 \"ip_%d\")," % (i, i))
    puts("    error $(sprintf \"no such handler: %s\" $0),")
    puts("    label num_queries,")
    puts("    return %d," % len(queries))
    puts("    label num_nodes,")
    puts("    return %d," % len(nodes))
    for i in range(len(queries)):
        puts("    label query_%d," % i)
        puts("    return %s," % queries[i].name)
    for i in range(len(nodes)):
        (hostname, ip) = nodes[i]
        puts("    label host_%d," % i)
        puts("    return %s," % hostname)
        puts("    label ip_%d," % i)
        puts("    return %s," % ip)
    puts("end);")
    return "\n".join(lines)

def gen_live_packet_source(loglvls):
    # regular ol' live capture & channel control
    lines = []
    puts = lambda line: lines.append(line)
    args = ["DEVNAME $ARGOS_DEVNAME",
            "DLT $ARGOS_DATALINKTYPE",
            "IMMEDIATE true",
            "PROMISC true",
            "HEADROOM %d" % PKT_HEADROOM,
            "BURST 8"]
    puts("from_pcap::FromPcap(%s)" % ",".join(args))
    puts("wifi_chan::WifiChannel(DEVNAME $ARGOS_DEVNAME, INITIAL_CHAN 1, CHANGE_EUID true);")
    puts("chan_mgr::BasicChannelManager(wifi_chan.get_channel, wifi_chan.set_channel" + \
             ", LOGGING %s);" % loglvls["chan_mgr"])
    puts("from_pcap -> pktsrc::Null();")
    return "\n".join(lines)

def gen_nodeinfo_element(testbeds):
    lines = []
    puts = lambda line: lines.append(line)

    args = []
    for testbed, hostnames in testbeds.iteritems():
        for hostname in hostnames:
            node_id = hostname[-3:]
            base_ip = gethostbyname(hostname)
            mesh_ip = gethostbyname(hostname + "-mgmt")
            args.append("%s %s" % (hostname, node_id))
            args.append("%s %s" % (base_ip, node_id))
            args.append("%s %s" % (mesh_ip, node_id))
            
    puts("NodeInfo(%s)" % ",".join(args))
    return "\n".join(lines)

# peers argument should be a list of hostnames
# note: DirectIPLookup uses a ton of memory, so we use LinearIPLookup for routers
def gen_node_router(queries, generate_packet_source, toserver_port, overlay_port,
                    control_port, testbeds, coordinator, ol_queue_capac=1000,
                    ol_elt_params={}, queue_stats_ival=10, loglvls=None):

    def get_overlay_ip(host):
        if host == coordinator:
            return gethostbyname(coordinator)
        else:
            return gethostbyname("%s-mgmt" % host)

    if loglvls is None:
        loglvls = get_logging_defaults()

    # more convenient to have a list of peers' hostnames rather than a dict
    peers = []
    for testbed, hostnames in testbeds.iteritems():
        peers += hostnames

    # also include the coordinator as a peer!
    peers += [coordinator]

    # used to replace dots with underscores when hostnames are used as part of
    # an element name (which can't have dots in them)
    undot = lambda s: s.replace(".", "_")
    
    # node-side constants
    TCP_REASS_TIMEOUT = 10*60        # 10 minutes
    # (all others defined by individual nodes via parameter definitions)
    
    # unified router is assembled as a list of strings for efficiency
    lines = []
    puts = lambda line: lines.append(line)
    
    puts("// Script to allow query logic to access some runtime info")
    li = [(host, get_overlay_ip(host)) for host in peers if host != coordinator]
    puts(gen_inspect_script(queries, li))
    puts("")
    
    puts("// Element Classes")
    puts(gen_elementclasses(ol_queue_capac))
    puts("")
    puts(gen_annotation_info())
    puts("")
    
    puts("//  Base System Plumbing")
    puts("RandomSeed();")
    puts("sys::SystemInfo();")
    puts("loghandler::LogHandler();")
    puts("ControlSocket(\"TCP\", %d, LOCALHOST false);" % control_port)
    import getpass
    puts("ChangeUID(%s);" % getpass.getuser())
    puts(gen_nodeinfo_element(testbeds))
    puts("")
    
    # some crap to deal with nodes that need SSH tunnels
    puts("toserver_tunnel::SSHTunnel(%d, %s, %d, LOCAL_HOST localhost, LOGIN $ARGOS_SSH_LOGIN, ID_FILE $ARGOS_SSH_ID_FILE, SUDO %d)" % \
         (toserver_port+10000, coordinator, toserver_port, os.getuid()))
    puts("overlay_tunnel::SSHTunnel(%d, %s, %d, LOCAL_HOST localhost, LOGIN $ARGOS_SSH_LOGIN, ID_FILE $ARGOS_SSH_ID_FILE, SUDO %d)" % \
         (overlay_port+10000, coordinator, overlay_port, os.getuid()))
    puts("Script(goto end $(eq $ARGOS_SSH_TUNNEL 0),")
    puts("       write toserver_tunnel.open,")
    puts("       write to_server_proxy.dst localhost:%d," % (toserver_port+10000))
    puts("       write overlay_tunnel.open,")
    puts("       write ol_out_proxy_%s.dst localhost:%d," % (undot(coordinator), overlay_port+10000))
    puts(");")
    puts("Script(goto end $(eq $ARGOS_SSH_TUNNEL 0), wait 60,")
    puts("  goto begin $(eq $(toserver_tunnel.connected) 1),")
    puts("  write toserver_tunnel.open, loop);")
    puts("Script(goto end $(eq $ARGOS_SSH_TUNNEL 0), wait 60,")
    puts("  goto begin $(eq $(overlay_tunnel.connected) 1),")
    puts("  write overlay_tunnel.open, loop);")
    puts("")
    
    # create ScheduleInfo element - some 'base system' elements get inflated
    # scheduling priorities to try and ensure they take priority
    puts("ScheduleInfo(from_pcap 32,")
    puts("    wifi_ol 10,")
    puts("    ol_in_proxy 6,")
    for peer in peers:
        puts("    ol_out_proxy_%s 10," % undot(peer))
    puts("    to_server_proxy 10,")
    puts("    wifi_merge 3,")
    for i in range(len(queries)):
        puts("    q%d %.4f," % (i, queries[i].priority))
    puts(");")
    puts("")

    # Create a NetworkProxy (fed by a StrideSched) for queries to use to send
    # packets to the server
    args = []

    # input 1 of to_server is for log messages; we give it the default number of
    # tickets
    args.append("%d" % DEF_QUERY_PRIORITY)
    for i in range(len(queries)):
        args.append("%d" % queries[i].priority)
    puts("to_server::NumberedStrideSched(%s)" % ", ".join(args))
    
    args = ["DST %s" % coordinator,
            "PORT %d" % toserver_port,
            "LOCAL_IP $ARGOS_OVERLAY_IP",
            "LOGGING %s" % loglvls["net_proxy"],
            "BURST 8"]
    puts("    -> to_server_proxy::NetworkProxy(%s);" % ", ".join(args))
    puts("")
    
    # connect the loghandler to port 0 of the to-server network proxy
    puts("loghandler[0] -> log_queue::Queue()")
    puts("              -> log_out::Counter()")
    puts("              -> [0]to_server;  // log messages")
    puts("log_queue[1] -> log_drops::Counter() -> Discard;")
    puts("")
    
    # create and connect WifiOverlay
    kwargs = { "COORDINATOR": coordinator,
               "LOCAL_IP": "$ARGOS_OVERLAY_IP",
               "TRACKER": "assoc",
               "STICKY_ROUTES": "true",
               "LOGGING": loglvls["wifi_ol"] }
    
    for param, val in ol_elt_params.iteritems():
        kwargs[param] = val

    args = []
    for param, val in kwargs.iteritems():
        args.append("%s %s" % (param, val))

    puts("wifi_ol::WifiOverlay(%s);" % ", ".join(args))
    puts("wifi_ol[1] -> ol_waitq_drops::Counter() -> Discard;")
    puts("ol_from_net_to_wifiol::SetPacketType(OTHERHOST, FROM HOST) -> wifi_ol;")
    puts("aggregated_tee::Tee();")
    puts("")

    # handle packets outgoing from WifiOverlay
    puts("// Outgoing WifiOverlay Traffic")
    puts("ol_ttl_drops::Counter() -> Discard;")
    puts("ol_out_router::LinearIPLookup(/* port 0 is intentionally unassigned */")
    puts("        0.0.0.0/32 1 /* unroutable packets */,")
    puts("        0.0.0.1/32 2 /* packets with broadcast bssid */,")
    puts("        255.255.255.255/32 3 /* broadcast packets (to all peers) */,")
    for i in range(len(peers)):
        ip = get_overlay_ip(peers[i])
        puts("        %s/32 %d," % (ip, i+4))
    puts("        0.0.0.0/0 %d /* all others */);" % (len(peers)+4))
    puts("ol_out_router[0] -> ol_to_self::PacketTypeSwitch();  // dst-IP = [self]")
    puts("ol_out_router[1] -> ol_out_unclassified::Counter() -> aggregated_tee;  // dst-IP = 0.0.0.0")
    puts("ol_out_router[2] -> ol_out_bcast_bssid::Counter() -> aggregated_tee;  // dst-IP = 0.0.0.1");
    puts("ol_out_router[3] -> ol_out_all_peers::Counter() -> ol_bcast_tee::Tee();  // dst-IP = 255.255.255.255");
    for i in range(len(peers)):
        ip = get_overlay_ip(peers[i])
        puts("ol_out_router[%d] -> ol_ttl_check_%s::CheckPaint(0, ANNO 27) -> ol_ttl_drops;" % (i+4, undot(peers[i])))
        puts("ol_ttl_check_%s[1] -> ol_out_queue_%s::WifiOverlayQueue()" % (undot(peers[i]), undot(peers[i])))
        puts("    -> ol_out_proxy_%s::NetworkProxy(DST %s, PORT %d, LOCAL_IP $ARGOS_OVERLAY_IP, LOGGING %s);" % \
             (undot(peers[i]), ip, overlay_port, loglvls["wifi_ol"]))
        puts("ol_bcast_tee[%d] -> ol_out_queue_%s;" % (i, undot(peers[i])))
        puts("ol_out_queue_%s[1] -> Discard;" % undot(peers[i]))  # todo - QueueWatcher

    # should never happen if all nodes are configured the same:
    puts("ol_out_router[%d] -> PacketError(wifi_ol, \"unknown dst-ip from wifi_ol\")" % (len(peers)+4))
    puts("    -> Print(\"ERROR: unknown dst-ip from wifi_ol\", 8, PRINTANNO true, PRINTTYPE true) -> Discard;")
    puts("")
    puts("// reroute packets destined for myself to output port 0")
    puts("Script(write ol_out_router.set $ARGOS_OVERLAY_IP 0);")
    puts("// 0 = HOST, 1 = BROADCAST, 2 = MULTICAST, 3 = OTHERHOST, 4 = OUTGOING, 5 = LOOPBACK, 6 = FASTROUTE")
    puts("ol_to_self[0] -> ol_self_to_self::Counter() -> aggregated_tee;  // process locally")
    puts("ol_to_self[1] -> PacketError(wifi_ol, \"unexpected PacketType (1) from wifi_ol to self\") -> Discard;")
    puts("ol_to_self[2] -> PacketError(wifi_ol, \"unexpected PacketType (2) from wifi_ol to self\") -> Discard;")
    puts("ol_to_self[3] -> ol_net_to_self::Counter() -> aggregated_tee;  // process locally")
    puts("ol_to_self[4] -> PacketError(wifi_ol, \"unexpected control packet from wifi_ol to self\") -> Discard;")
    puts("ol_to_self[5] -> PacketError(wifi_ol, \"unexpected PacketType (5) from wifi_ol to self\") -> Discard;")
    puts("ol_to_self[6] -> PacketError(wifi_ol, \"unexpected PacketType (6) from wifi_ol to self\") -> Discard;")
    puts("")

    # handle packets incoming to WifiOverlay
    puts("// Incoming WifiOverlay Traffic")
    args = [ "PORT %d" % overlay_port, "HEADROOM %d" % PKT_HEADROOM, "LOGGING %s" % loglvls["wifi_ol"]]
    puts("ol_in_proxy::NetworkProxyServer(%s)" % ", ".join(args))
    puts("    -> ol_in_router::LinearIPLookup(")
    for i in range(len(peers)):
        ip = get_overlay_ip(peers[i])
        puts("        %s/32 %d," % (ip, i))
    puts("        0.0.0.0/0 %d /* all others */);" % len(peers))
    for i in range(len(peers)):
        puts("ol_in_router[%d] -> ol_in_path_%s::WifiOverlayPath() -> ol_from_net_to_wifiol;" % \
             (i, undot(peers[i])))

    # print an error when anything is received from an unknown node
    puts("ol_in_router[%d] -> PacketError(wifi_ol, \"unknown src-ip from ol_in_router\")" % len(peers))
    puts("    -> Print(\"ERROR: unknown src-ip from ol_in_router\", 8, PRINTANNO true, PRINTTYPE true) -> Discard;")
    puts("")

    # call the packet-source generator, which should append lines that create the
    # following elements: FromPcap, BasicChannelManager, and WifiChannel
    # the output element must be named pktsrc
    puts(generate_packet_source(loglvls))
    puts("")

    # create node queries as compound elements, using default if needed
    puts("//  User Queries")
    for i in range(len(queries)):
        query = queries[i]
        puts("ArgosQuery(QUERY q%d, PRIORITY %d);" % (i, query.priority))
        puts("q%d::{ %s };" % (i, query.node_router))
        # the PaintSwitch element directs the packet to the appropriate input
        # port of the query
        puts("q%d_in::Counter() -> q%d_ps::PaintSwitch();" % (i, i))
        puts("")
    
    # connect each user query's output to the network proxy
    puts("//  Connections from User Queries to the NetworkProxy")
    
    server_port = 1  # leave port [0]to_server for log messages
    for i in range(len(queries)):
        query = queries[i]
        
        if query.node_router == "":
            # this query has no output
            puts("Idle -> q%d_out::Counter() -> Idle;" % i)
            puts("Idle -> q%d_drops::Counter() -> Idle;" % i)
        elif query.queuelen == 0:
            # this query uses a PULL output
            puts("q%d -> q%d_out::Counter() -> [%d]to_server;" % (i, i, server_port))
            puts("Idle -> q%d_drops::Counter() -> Idle;" % i)
            server_port += 1
        else:
            # this query uses a PUSH output to a Queue
            puts("q%d -> q%d_queue::Queue(%d) -> q%d_out::Counter() -> [%d]to_server;" % \
                 (i, i, query.queuelen, i, server_port))
            puts("q%d_queue[1] -> q%d_drops::Counter() -> Discard;" % (i, i))
            server_port += 1
    puts("")


    # check if ALL queries implement a packet filter, and therefore we can
    # exercise them
    do_packet_filtering = True
    filters = 0
    s = set([elt for elt in TAP_NAMES if elt != "raw"])
    for query in queries:
        # if any query does not provide a packet filter config AND uses a node
        # tap other than 'raw', then this query implicity requests all packets
        # (i.e. filtering none) so we just skip packet filtering all together
        if query.packet_filter == "":
            if len(s.intersection(set(query.node_taps))) > 0:
                do_packet_filtering = False
                break
        else:
            filters += 1

    puts("//  Query Packet Filter")
    puts("query_pkt_filter::{")
    if do_packet_filtering:
        # rare case
        if filters == 0:
            print "warning: queries implicitly filter all packets (none will be aggregated)"
            puts("input -> [1]output; Idle -> output")  # reject everything
        else:
            puts("    out_c::Counter() -> cp::CheckPaint(1) -> output;")
            puts("    cp[1] -> [1]output;")
            puts("    input -> rs::RandomSample(DROP 0.001) -> in_c::Counter() -> Paint(0)")
            for i in range(len(queries)):
                query = queries[i]
                if query.packet_filter != "":
                    puts("        -> filter%d::{ %s }" % (i, query.packet_filter))
                    puts("        -> fcp%d::CheckPaint(1)" % i)
                    puts("        -> out_c;")
                    puts("    fcp%d[1]" % i)
                # else, it must be the case that this query doesn't use any node taps
                # other than raw
            puts("        -> out_c;")
            puts("    rs[1] -> Script(TYPE PACKET, goto end $(eq $(in_c.count) $(out_c.count)),")
            puts("                     set msg $(sprintf \"packet filter error; in=%d, out=%d\"")
            puts("                               $(in_c.count) $(out_c.count)),")
            puts("                     write loghandler.log queries ERROR \"$(msg)\", return 0)")
            puts("        -> in_c;")
    else:
        # accept everything
        puts("input -> output; Idle -> [1]output;")
    puts("}")
    puts("")

    # figure out which taps are actually needed (based on the queries)
    max_tap_needed = -1
    for query in queries:
        for tap in query.node_taps:
            max_tap_needed = max(max_tap_needed, tap_index(tap))

    if max_tap_needed < (len(TAP_NAMES)-1):
        print "warning: network taps truncated prior to '%s' tap" % TAP_NAMES[max_tap_needed+1]

    # assemble chain of network processing elements (with taps)
    puts("//  Network Stack")
    puts("pktsrc -> RadiotapDecap()")
    puts("    -> pre_capt_cnt::Counter()")
    puts("    -> filter_a::BSSIDFilter(12:00:00:00:00:00)")
    puts("    -> filter_b::BSSIDFilter(12:00:00:00:00:01)")
    puts("    -> filter_c::BSSIDFilter(12:00:00:00:00:02)")
    puts("    -> post_capt_cnt::Counter()")
    puts("    -> WifiStripFCS()")
    puts("    -> SetSniffer(SNIFFER $ARGOS_OVERLAY_IP)")  # sets channel & flags to 0
    puts("    -> assoc::AssocTracker(LOGGING WARNING, NETLOG WARNING)")
    puts("    -> chan_mgr")
    if max_tap_needed == tap_index("raw"):
        puts("    -> raw_tee::Tee();")
        puts("Idle")
    else:
        puts("    -> raw_tee::Tee()")
    puts("    -> query_pkt_filter")
    puts("    -> query_accepted::Counter()")
    puts("    -> SetPacketType(HOST)     // mark packet as locally captured")
    puts("    -> Paint(%d, ANNO 27)      // initialize TTL field" % len(peers))
    puts("    -> wifi_ol")
    puts("    -> ol_out_router;")
    puts("")
    puts("query_pkt_filter[1] -> query_filtered::Counter() -> Discard;")

    puts("")
    if max_tap_needed == tap_index("aggregated"):
        puts("Idle")
    else:
        puts("aggregated_tee")
        
    puts("    -> adj_skew::AdjustTimeSkew(WARMUP %d, LOGGING %s)" % \
         (TIMESKEW_WARMUP, loglvls["adj_skew"]))
    puts("    -> TimestampSort()")
    puts("    -> wifi_merge_in::Counter()")
    puts("    -> wifi_merge::WifiMerge(HIMEM %d, LOGGING %s)" % \
         (WIFIMERGE_HIMEM, loglvls["wifi_merge"]))
    puts("    -> Paint(0)  // mark as not a dupe")
    puts("    -> wifi_merge_out::Counter()")
    puts("    -> wmd::WifiMergeDecap()")
    puts("    -> bcn_cl::Classifier(0/00%0c 0/80%f0, -)  // beacon frames")
    puts("    -> WifiMergeUnstrip()")
    puts("    -> [1]adj_skew[1]")
    puts("    -> WifiMergeDecap()")
    puts("    -> skew_mux::Null()")
    puts("    -> GuessChannel(TRACKER assoc)")
    if max_tap_needed == tap_index("merged"):
        puts("    -> merged_tee::Tee();")
        puts("Idle")
    else:
        puts("    -> merged_tee::Tee()")
    puts("    -> WifiEtherClassifier(0x0800) /* IP packets */")
    puts("    -> WifiDecap(ETHER false)")
    puts("    -> check_ip::CheckIPHeader(CHECKSUM false)")
    puts("    -> ip_reass::IPReassembler(HIMEM $ARGOS_IP_REASS_HIMEM)")
    if max_tap_needed == tap_index("ip"):
        puts("    -> ip_tee::Tee();")
        puts("Idle")
    else:
        puts("    -> ip_tee::Tee()")
    puts("    -> IPClassifier(\"tcp\")")
    puts("    -> StripIPHeader")
    puts("    -> tcp_reass::TCPReassembler(HIMEM $ARGOS_IP_REASS_HIMEM, TIMEOUT %d)" % \
                 (TCP_REASS_TIMEOUT))
    if max_tap_needed == tap_index("tcp"):
        puts("    -> tcp_tee::Tee();")
    else:
        puts("    -> Discard();")

    puts("filter_a[1] -> filter_cnt::Counter() -> Discard;")
    puts("filter_b[1] -> filter_cnt;")
    puts("filter_c[1] -> filter_cnt;")
    puts("wifi_merge[1] -> wifi_merge_dupes::Counter() -> Paint(1) -> wmd;")
    puts("bcn_cl[1] -> skew_mux;  // non-beacon frames")
    puts("")
    
    puts("//  User Query Network Taps")

    next_tap_output = [0] * len(TAP_NAMES)
    next_query_input = {}  # key = query index

    for i in range(max_tap_needed):
        next_tap_output[i] = 1

    # connect user queries to the taps they requested
    for i in range(len(queries)):
        query = queries[i]
        if len(query.node_taps) == 0:
            puts("Idle -> q%d_in;" % i)
        else:
            for j in range(len(TAP_NAMES)):
                if TAP_NAMES[j] in query.node_taps:
                    query_port = next_query_input.get(i, 0)
                    # the Paint element is used to mark which input port (of the
                    # query) this packet should be pushed into
                    if query.incl_dupes:
                        puts("%s_tee[%d] -> Paint(%d) -> q%d_in;" % \
                             (TAP_NAMES[j], next_tap_output[j], query_port, i))
                    else:
                        # the CheckPaint element filters out packets which were
                        # marked as WifiMerge duplicates
                        puts("%s_tee[%d] -> CheckPaint(0) -> Paint(%d) -> q%d_in;" % \
                             (TAP_NAMES[j], next_tap_output[j], query_port, i))
                    puts("q%d_ps[%d] -> [%d]q%d;" % (i, query_port, query_port, i))
                    next_tap_output[j] += 1
                    next_query_input[i] = query_port + 1

    return "\n".join(lines)

def gen_offline_packet_source(loglvls, filename, timing=True, sync=None, drop=None):
    lines = []
    puts = lambda line: lines.append(line)

    if timing:
        timing_arg = "true"
    else:
        timing_arg = "false"
    
    puts("Script(set msg $(sprintf \"reading from dumpfile %s on %%s\" $(sys.hostname))," % filename)
    puts("    write loghandler.log from_dump INFO \"$(msg)\");")
    puts("from_dump::FromDump(%s, TIMING %s, MMAP false, ACTIVE false, END_CALL from_dump_done.c);" % \
         (filename, timing_arg))
    puts("from_pcap::Script(TYPE PROXY,")
    puts("    goto notkrecv $(ne $0 kernel_recv), return $(from_dump.count),")
    puts("    label notkrecv, goto notkdrop $(ne $0 kernel_drops), return 0,")
    puts("    label notkdrop, goto notdlt $(ne $0 dlt), return 0,")
    puts("    label notdlt, goto notmdrop $(ne $0 mem_drops), return 0,")
    puts("    label notmdrop, goto notreset $(ne $0 reset), write from_dump.reset_counts,")
    puts("    label notreset, return 'invalid from_pcap handler');")
    puts("wifi_chan::Script(TYPE PROXY, return 0);")
    puts("chan_mgr::BasicChannelManager(wifi_chan.get_channel, wifi_chan.set_channel,")
    puts("    ACTIVE false, LOGGING %s);" % loglvls["chan_mgr"])
    puts("from_dump_done::Script(TYPE PROXY,")
    puts("    set msg $(sprintf \"dumpfile exhausted on %s\" $(sys.hostname)),")
    puts("    write loghandler.log from_dump INFO \"$(msg)\");")
    puts("Script(goto okencap $(eq \"$(from_dump.encap)\" \"802_11_RADIO\"),")
    puts("    write stopper.foo,")
    puts("    error $(sprintf \"unsupported from_dump.encap (%s)\" $(from_dump.encap)),")
    puts("    label okencap,")
    puts("    return);")
    puts("stopper::Script(TYPE PROXY, wait 0.1, stop);")
    
    if sync is None:
        # wait 12 seconds before starting file read
        puts("Script(wait 12,")
        puts("    set msg $(sprintf \"dumpfile activated on %s\" $(sys.hostname)),")
        puts("    write loghandler.log from_dump INFO \"$(msg)\",")
        puts("    write from_dump.active true);")
    else:
        # wait until sync time
        puts("Script(set diff $(sub %f $(now))," % sync)
        puts("    goto toolate $(lt $diff 0),")
        puts("    wait $diff,")
        puts("    set msg $(sprintf \"FromDump activated on %s\" $(sys.hostname)),")
        puts("    write loghandler.log from_dump INFO \"$(msg)\",")
        puts("    write from_dump.active true, return,")
        puts("    label toolate,")
        puts("    set msg $(sprintf \"FromDump sync time already passed on %s\" $(sys.hostname)),")
        puts("    write loghandler.log from_dump WARNING \"$(msg)\");")

    if drop is None:
        puts("from_dump -> pktsrc::Null();")
    else:
        puts("from_dump -> pktsrc::RandomSample(DROP %f);" % drop)
    return "\n".join(lines)

# testbeds should be a map from a testbed name (string) to a list of hostnames
# note: DirectIPLookup uses a ton of memory, so we use LinearIPLookup for routers
def gen_server_router(queries, node_file, toserver_port, overlay_port, control_port,
                      testbeds, coordinator, ol_queue_capac=1000,
                      ol_elt_params={}, loglvls=None,
                      config_port=DEF_CONFIG_PORT, definitions={}):

    def get_accessible_ip(host):
        # For the server's outgoing overlay connections, we do NOT connect
        # specifically to the management IP of each node (like we do on the
        # nodes) because some nodes' management interfaces are not reachable from
        # the server - instead we use the canonical hostname and let the DNS
        # server direct us to the right IP to access.
        return gethostbyname(host)

    def get_overlay_ip(host):
        return gethostbyname("%s-mgmt" % host)

    if loglvls is None:
        loglvls = get_logging_defaults()

    # used to replace dots with underscores when hostnames are used as part of
    # an element name (which can't have dots in them)
    undot = lambda s: s.replace(".", "_")

    # sometimes its more convenient to have a list of (testbed, hostname) tuples
    # for all of the nodes
    nodes = []
    for testbed, hostnames in testbeds.iteritems():
        for hostname in hostnames:
            nodes.append((testbed, hostname))
    
    # server-side constants
    IP_REASS_HIMEM = 1024*1024       # 1 MB
    TCP_REASS_HIMEM = 10*1024*1024   # 10 MB
    TCP_REASS_TIMEOUT = 10*60        # 10 minutes
    MEM_LOW_LIMIT = 512*1024*1024    # 512 MB
    MEM_HIGH_LIMIT = 1024*1024*1024  # 1 GB

    # unified router is assembled as a list of strings for efficiency
    lines = []
    puts = lambda line: lines.append(line)

    # a few parameter definitions are required
    if "ARGOS_OVERLAY_IP" not in definitions:
        definitions["ARGOS_OVERLAY_IP"] = gethostbyname(coordinator)

    for key, value in definitions.items():
        puts("define($%s %s);" % (key, value))
    puts("")

    puts("// Script to allow query logic to access some runtime info")
    li = [(host, get_overlay_ip(host)) for (tb, host) in nodes]
    puts(gen_inspect_script(queries, li))
    puts("")

    puts("// Element Classes")
    puts(gen_elementclasses(ol_queue_capac))
    puts("")
    puts(gen_annotation_info())
    puts("")
    
    puts("//  Base System Plumbing")
    puts("RandomSeed();")
    puts("sys::SystemInfo();")
    # since this is running on the server, all loghandler output is dropped;
    # also, the local-logging threshold is DATA instead of the default (INFO)
    puts("loghandler::LogHandler(LOGGING DATA);")
    puts("ControlSocket(\"TCP\", %d, LOCALHOST true);" % control_port)
    puts(gen_nodeinfo_element(testbeds))
    puts("")

    # include database only if ARGOS_DATABASE_USER is included in the definitions
    # (yes, this is a little hacky but this method already has lots of arguments
    # so I don't really want to add even more)
    if "ARGOS_DATABASE_USER" in definitions:
        puts("//  Database Connection")
        puts("db::PostgreSQL(DATABASE $ARGOS_DATABASE_DBNAME,")
        puts("               USER $ARGOS_DATABASE_USER,")
        puts("               PASSWORD $ARGOS_DATABASE_PASSWORD);")

    # create ArgosCtrlServer element
    args = ["LOGGING %s" % loglvls["ctrl_server"],
            "NODE_FILE %s" % node_file,
            "PORT %d" % config_port]

    # just to make sure we cover everything (e.g. in case some of the /etc/hosts
    # entries are off) we allow connections from 2 (possibly identical IPs) from
    # each node; its default IP (resolving its base hostname) and its mesh IP
    # (resolving hostname+"-mgmt")
    allow_ips = []
    for testbed, hostname in nodes:
        base_ip = gethostbyname(hostname)
        mesh_ip = gethostbyname(hostname + "-mgmt")
        allow_ips.append(base_ip)
        if mesh_ip != base_ip:
            allow_ips.append(mesh_ip)

    args.append("ALLOW \"%s\"" % " ".join(allow_ips))
    
    puts("ctrl_server::ArgosCtrlServer(%s);" % ", ".join(args))

    # create ScheduleInfo element - some 'base system' elements get inflated
    # scheduling priorities to try and ensure they take priority
    puts("ScheduleInfo(from_nodes_proxy 5,")
    for testbed in testbeds.keys():
        puts("    wifi_ol_%s 10," % testbed)
    puts("    ol_in_proxy 6,")
    for testbed, hostname in nodes:
        puts("    ol_out_proxy_%s 10," % undot(hostname))
    for i in range(len(queries)):
        puts("    q%d %.4f," % (i, queries[i].priority))
    puts(");")
    puts("")

    # create and connect WifiOverlay elements
    kwargs = { "COORDINATOR": "self",
               "LOCAL_IP": "$ARGOS_OVERLAY_IP",
               "TRACKER": "assoc",
               "STICKY_ROUTES": "true",
               "LOGGING": loglvls["wifi_ol"] }
    
    for param, val in ol_elt_params.iteritems():
        kwargs[param] = val

    args = []
    for param, val in kwargs.iteritems():
        args.append("%s %s" % (param, val))
    
    puts("ol_waitq_drops::Counter() -> Discard;")
    puts("ol_ttl_drops::Counter() -> Discard;")
    puts("")
    for testbed in testbeds.keys():
        puts("wifi_ol_%s::WifiOverlay(%s);" % (testbed, ", ".join(args)))
        puts("wifi_ol_%s[1] -> PacketError(wifi_ol_%s, \"output from port 1\")" % (testbed, testbed))
        puts("    -> Print(\"ERROR: output from port 1\", 256, PRINTANNO true, PRINTTYPE true)")
        puts("    -> ol_waitq_drops;")
    puts("")
    
    # handle packets outgoing from WifiOverlay
    puts("// Outgoing WifiOverlay Traffic (should be all control packets)")
    puts("")
    for testbed, hostnames in testbeds.iteritems():
        puts("// '%s' testbed:" % testbed)
        router = "ol_out_rtr_%s" % testbed
        puts("wifi_ol_%s[0] -> %s::LinearIPLookup(" % (testbed, router))
        puts("        255.255.255.255/32 0 /* broadcast to all peers */,")
        for i in range(len(hostnames)):
            hostname = hostnames[i]
            base_ip = gethostbyname(hostname)
            mesh_ip = gethostbyname(hostname + "-mgmt")
            puts("        %s/32 %d," % (base_ip, i+1))
            if mesh_ip != base_ip:
                puts("        %s/32 %d," % (mesh_ip, i+1))
        puts("        0.0.0.0/0 %d /* all others */);" % (len(hostnames)+1))

        puts("%s[0] -> ol_bcast_tee_%s::Tee();  // dst-IP = 255.255.255.255" % (router, testbed))
        for i in range(len(hostnames)):
            hostname = hostnames[i]
            ip = get_accessible_ip(hostname)
            puts("%s[%d] -> ol_ttl_check_%s::CheckPaint(0, ANNO 27) -> ol_ttl_drops;" % \
                 (router, i+1, undot(hostname)))
            puts("ol_ttl_check_%s[1] -> ol_out_queue_%s::WifiOverlayQueue()" % \
                 (undot(hostname), undot(hostname)))
            puts("    -> ol_out_proxy_%s::NetworkProxy(DST %s, PORT %d, LOCAL_IP $ARGOS_OVERLAY_IP, LOGGING %s);" % \
                 (undot(hostname), ip, overlay_port, loglvls["wifi_ol"]))

            puts("ol_bcast_tee_%s[%d] -> ol_out_queue_%s;" % (testbed, i, undot(hostname)))
            puts("ol_out_queue_%s[1] -> Discard;" % undot(hostname)) # todo - QueueWatcher
    
        # should never happen if all nodes are configured the same:
        puts("%s[%d] -> PacketError(wifi_ol_%s, \"unknown dst-ip from wifi_ol\")" % \
             (router, len(hostnames)+1, testbed))
        puts("    -> Print(\"ERROR: unknown dst-ip from wifi_ol_%s\", 8, PRINTANNO true, PRINTTYPE true)" % testbed)
        puts("    -> Discard;")
        puts("")
    
    # handle packets incoming to WifiOverlay
    puts("// Incoming WifiOverlay Traffic (should be all control packets)")
    args = [ "PORT %d" % overlay_port, "LOGGING %s" % loglvls["wifi_ol"]]
    puts("ol_in_proxy::NetworkProxyServer(%s)" % ", ".join(args))
    puts("    -> ol_in_router::LinearIPLookup(")
    for i in range(len(nodes)):
        (testbed, hostname) = nodes[i]
        ip = gethostbyname("%s-mgmt" % hostname)
        puts("        %s/32 %d," % (ip, i))
    puts("        0.0.0.0/0 %d /* all others */);" % len(nodes))
    for i in range(len(nodes)):
        (testbed, hostname) = nodes[i]
        puts("ol_in_router[%d] -> ol_in_path_%s::WifiOverlayPath()" % (i, undot(hostname)))
        puts("    -> SetPacketType(OTHERHOST, FROM HOST)")
        puts("    -> wifi_ol_%s;" % testbed)
        
    # print an error when anything is received from an unknown node
    puts("ol_in_router[%d] -> PacketError(wifi_ol, \"unknown src-ip from ol_in_router\")" % len(nodes))
    puts("    -> Print(\"ERROR: unknown src-ip from ol_in_router\", 8, PRINTANNO true, PRINTTYPE true) -> Discard;")
    puts("")

    puts("// create some dummy elements to emulate real elements that exist in the")
    puts("// node-side config - this allows us to use scripts that reference these")
    puts("// elements both in the node-side and server-side configs")
    puts("Idle -> ol_out_queue_%s::WifiOverlayQueue() -> Idle;" % undot(coordinator))
    puts("ol_out_queue_%s[1] -> Idle;" % undot(coordinator))
    puts("Idle -> ol_in_path_%s::WifiOverlayPath() -> Idle;" % undot(coordinator))
    puts("ol_out_proxy_%s::Script(TYPE PROXY, return 0);" % undot(coordinator))
    puts("Idle -> ol_out_unclassified::Counter() -> Idle;")
    puts("Idle -> ol_out_bcast_bssid::Counter() -> Idle;")
    puts("Idle -> ol_self_to_self::Counter() -> Idle;")
    puts("Idle -> ol_net_to_self::Counter() -> Idle;")
    puts("")
    
    # create (dummy) AssocTracker for use by WifiOverlay
    puts("Idle -> assoc::AssocTracker() -> Idle;  // does nothing, but needed by WifiOverlay")
    puts("")

    # create server queries as compound elements, using default if needed
    puts("//  User Queries")
    for i in range(len(queries)):
        query = queries[i]
        puts("q%d::{ %s };" % (i, query.server_router))
        puts("")
        
    # create NetworkProxyServer: output 1 goes to the log-handler, and each
    # other output i goes to query i-1
    puts("//  NetworkProxyServer element")

    args = [ "PORT %d" % toserver_port,
             "LOGGING %s" % loglvls["net_proxy"]]
    puts("from_nodes_proxy::NetworkProxyServer(%s)" % ", ".join(args))
    puts("    -> from_nodes_switch::NumberedSwitch();")
    puts("")
    puts("from_nodes_switch[0] -> loghandler;")
    puts("")
    
    next_query_input = {}  # key = query index
    
    puts("//  NetworkProxyServer connections to User Queries")
    for i in range(len(queries)):
        # leave port netproxy[0] for log messages
        query = queries[i]
        if query.server_router == "":
            puts("from_nodes_switch[%d] -> Discard;" % (i+1))
        else:
            puts("from_nodes_switch[%d] -> [0]q%d;" % (i+1, i))
        next_query_input[i] = 1
    puts("")

    return "\n".join(lines)

def get_logging_defaults():
    return { "adj_skew": "INFO",
             "ctrl_server": "INFO",
             "chan_mgr": "INFO",
             "net_proxy": "INFO",
             "proxyserver": "INFO",
             "wifi_merge": "INFO",
             "wifi_ol": "INFO",
             }

def init():
    global ANNO_OFFSETS
    global ANNO_SIZES

    fi = open("include/argos/anno.h")
    for line in fi:
        match = re.match("\s*#define\s+(.+)_ANNO_OFFSET\s+(\d+)", line)
        if match is not None:
            ANNO_OFFSETS[match.group(1)] = int(match.group(2))
            continue
        match = re.match("\s*#define\s+(.+)_ANNO_SIZE\s+(\d+)", line)
        if match is not None:
            ANNO_SIZES[match.group(1)] = int(match.group(2))
            continue

    fi.close()

# returns a list of key->value dicts (one per query section)
def lex_config(config):
    tokens = shlex.split(config, comments=True)
    sections = []

    entry = 1
    try:
        while len(tokens) > 0:
            # expect an open curly brace
            if tokens[0] == "{":
                tokens.pop(0)
            else:
                raise ValueError("expected '{'")

            d = dict()

            while len(tokens) > 0 and tokens[0] != "}":
                (key, op, value) = tokens[0].partition("=")
                tokens.pop(0)

                if op == "=":
                    tokens.insert(0, value)
                    tokens.insert(0, op)
                    tokens.insert(0, key)
                    continue
                
                if len(tokens) == 0 or tokens[0] != "=":
                    raise ValueError("expected '=' after '%s'" % key)
                tokens.pop(0)

                if len(tokens) == 0:
                    raise ValueError("expected value for '%s'" % key)
                value = tokens[0]
                tokens.pop(0)
                
                d[key] = value

            # expect a close curly brace
            if len(tokens) > 0 and tokens[0] == "}":
                tokens.pop(0)
            else:
                raise ValueError("expected '}'")

            sections.append(d)
            entry += 1
        
        return sections
    
    except ValueError, e:
        raise ParseError("syntax error in block %d: %s" % (entry, e.message))

def parse_bool(val, field):
    val = val.lower()
    if val in ["false", "f", "n", "no", "0"]:
        return False
    elif val in ["true", "t", "y", "yes", "1"]:
        return True
    else:
        raise ValueError("%s field must be a boolean value" % field)

# returns a list of ArgosQuery objects
def parse_config(config):
    sections = lex_config(config)

    queries = []
    for i in range(len(sections)):
        try:
            vals = sections[i]
            query = ArgosQuery()
            query.name = "query_%d" % (i+1)
            query.active = True

            for key, val in vals.iteritems():
                if key == "name":
                    if val == "":
                        raise ValueError("value is required for '%s' field" % key)
                    else:
                        query.name = val
                elif key == "active":
                    if not parse_bool(val, "active"):
                        query.active = False
                        break
                elif key == "node_router":
                    query.node_router = parse_router(val)
                elif key == "server_router":
                    query.server_router = parse_router(val)
                elif key == "node_taps":
                    query.node_taps = parse_taps(val)
                elif key == "packet_filter":
                    query.packet_filter = parse_router(val)
                elif key == "priority":
                    if val == "":
                        raise ValueError("value is required for '%s' field" % key)
                    else:
                        query.priority = int(val)
                elif key == "queuelen":
                    if val == "":
                        raise ValueError("value is required for '%s' field" % key)
                    else:
                        v = int(val)
                        if v < 0:
                            raise ValueError("queuelen field must be >= 0")
                        query.queuelen = v
                elif key == "dupes":
                    query.incl_dupes = parse_bool(val, "dupes")
                else:
                    raise ValueError("unknown field: \"%s\"" % key)

            if not query.active:
                continue
            
            # make sure *something* was specified
            if query.node_router == "" and query.server_router == "":
                raise ValueError("must specify either node or server router")

            # check for nonsense combinations
            if query.node_router == "" and len(query.node_taps) > 0:
                raise ValueError("cannot specify node taps with no node router")

            queries.append(query)

        except ValueError, e:
            raise ParseError("syntax error in block %d: %s" % (i, e.message))
        
    return queries

def parse_router(config_entry):
    if config_entry.startswith("file://"):
        filename = config_entry[len("file://"):]
        fi = open(filename, "r")
        router = fi.read()
        fi.close()
        return router
    else:
        return config_entry

def parse_taps(config_entry):
    taps = []
    for field in config_entry.split(","):
        field = field.strip().lower()
        if field == "":
            continue
        if field not in TAP_NAMES:
            raise ValueError("invalid taps identifier: '%s'" % field)
        taps.append(field)
    return taps

def preprocess_config(filename, macros={}, warnings=True):
    cmd = ["gcc", "-E", "-x", "c"]
    for key, value in macros.iteritems():
        if value is None:
            cmd.append("-D%s" % key)
        else:
            cmd.append("-D%s=%s" % (key, value))
    cmd.append(filename)
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
    (out, err) = proc.communicate()

    if proc.returncode != 0:
        # looks like something went fatally wrong (note that gcc does NOT exit
        # with value 1 even if it emits warnings - this is good!)
        raise ValueError("gcc preprocessor failure: %s" % err)

    if warnings:
        for line in err.split("\n"):
            if line == "":
                continue
            else:
                print >>sys.stderr, "(gcc warning) %s" % line

    # gcc inserts comments (like '# 63 "config/run-snort.argos" 2') to keep track
    # of line-numbers and such, but if these are in the middle of a click config
    # then the click parser will get confused by them since click uses cpp-style
    # comments
    li = []
    for line in out.split("\n"):
        if line == "":
            continue
        elif line[0] == "#":
            continue
        else:
            li.append(line)

    return "\n".join(li) + "\n"

def tap_index(node_tap):
    return TAP_NAMES.index(node_tap)

def verify_router(router, name="router"):
    cmd = ["./bin/click-check", "-u"]
    proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    (out, err) = proc.communicate(router)
    out = out.strip()
    err = err.strip()

    if proc.returncode != 0:
        print >>sys.stderr, "%s failed validation by click-check:\n%s" % \
              (name, err)
        sys.exit(1)
