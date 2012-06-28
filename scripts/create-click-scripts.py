#!/usr/bin/env python

#
# IMPORTS
#

# system modules
from optparse import OptionParser
import os
import sys

# local modules
sys.path.append("lib/python")
import argos
import argosroutes


#
# METHODS
#
def append_peer_cmds(host, lines):
    puts = lambda s: lines.append("        %s" % s)
 
    # perform the same normalizations on hostname that argos.py does!
    undot = lambda s: s.replace(".", "_")
            
    # overall stats and compression performance on packets outgoing to [host]
    puts("set msg $(sprintf \"OUT-STATS host=%%s peer=%s queued-pkts=%%s queued-ctrl=%%s queued-bytes=%%s queued-reroutes=%%s drop-pkts=%%s drop-ctrl=%%s drop-bytes=%%s out-all=%%s send-bytes=%%s compress-rate=%%s avg-compress-size=%%s avg-cpu=%%s\"" % host)
    puts("    $(sys.hostname)")
    puts("    $(add $(ol_out_queue_%s/in_from_peers.count) $(ol_out_queue_%s/in_from_self.count))" % \
         (undot(host), undot(host)))
    puts("    $(ol_out_queue_%s/in_ctrl.count) $(ol_out_queue_%s/in_all.byte_count)" % \
         (undot(host), undot(host)))
    puts("    $(ol_out_queue_%s/in_from_peers.count)" % undot(host))
    puts("    $(add $(ol_out_queue_%s/drops_from_self.count) $(ol_out_queue_%s/drops_from_peers.count))" % \
         (undot(host), undot(host)))
    puts("    $(ol_out_queue_%s/drops_ctrl.count) $(ol_out_queue_%s/drops_all.byte_count)" % \
         (undot(host), undot(host)))
    puts("    $(ol_out_queue_%s/out_all.count) $(ol_out_proxy_%s.byte_count)" % \
         (undot(host), undot(host)))
    puts("    $(ol_out_proxy_%s.avg_compress_rate) $(ol_out_proxy_%s.avg_compress_size) " %
         (undot(host), undot(host)))
    puts("    $(ol_out_proxy_%s.avg_cpu))," % undot(host))
    puts("write loghandler.log wifi_ol DATA \"$(msg)\",")
    
    # packets enqueued to [host] with an unknown packet-type (should never happen)
    puts("goto no_in_unknown_%s $(eq $(ol_out_queue_%s/in_unknown.count) 0)," % \
         (undot(host), undot(host)))
    puts("set msg $(sprintf \"OUT-UNKNOWN-PKTS host=%%s peer=%s queued-pkts=%%s queued-bytes=%%s\"" % host)
    puts("    $(sys.hostname) $(ol_out_queue_%s/in_unknown.count)" % undot(host))
    puts("    $(ol_out_queue_%s/in_unknown.byte_count))," % undot(host))
    puts("write loghandler.log wifi_ol ERROR \"$(msg)\",")
    puts("label no_in_unknown_%s," % undot(host))
    
    # out-queue counter resets
    puts("write ol_out_proxy_%s.reset," % undot(host))
    puts("write ol_out_proxy_%s.reset_avgs," % undot(host))
    puts("write ol_out_queue_%s/in_all.reset," % undot(host))
    puts("write ol_out_queue_%s/out_all.reset," % undot(host))
    puts("write ol_out_queue_%s/drops_all.reset," % undot(host))
    puts("write ol_out_queue_%s/in_from_self.reset," % undot(host))
    puts("write ol_out_queue_%s/in_unknown.reset," % undot(host))
    puts("write ol_out_queue_%s/in_from_peers.reset," % undot(host))
    puts("write ol_out_queue_%s/in_ctrl.reset," % undot(host))
    puts("write ol_out_queue_%s/drops_from_self.reset," % undot(host))
    puts("write ol_out_queue_%s/drops_unknown.reset," % undot(host))
    puts("write ol_out_queue_%s/drops_from_peers.reset," % undot(host))
    puts("write ol_out_queue_%s/drops_ctrl.reset," % undot(host))
    
    # overall stats on packets received from [host]
    puts("set msg $(sprintf \"IN-STATS host=%%s peer=%s in-pkts=%%s in-ctrl=%%s in-bytes=%%s\"" % host)
    puts("    $(sys.hostname) $(add $(ol_in_path_%s/from_source.count) $(ol_in_path_%s/from_reroute.count))" % \
         (undot(host), undot(host)))
    puts("    $(ol_in_path_%s/ctrl.count) $(ol_in_path_%s/all.byte_count))," % \
         (undot(host), undot(host)))
    puts("write loghandler.log wifi_ol DATA \"$(msg)\",")
    
    # packets received from [host] with an unknown packet-type (should never happen)
    puts("goto no_recv_unknown_%s $(eq $(ol_in_path_%s/unknown.count) 0)," % \
         (undot(host), undot(host)))
    puts("set msg $(sprintf \"IN-UNKNOWN-PKTS host=%%s peer=%s in-pkts=%%s in-bytes=%%s\"" % host)
    puts("    $(sys.hostname) $(ol_in_path_%s/unknown.count)" % undot(host))
    puts("    $(ol_in_path_%s/unknown.byte_count))," % undot(host))
    puts("write loghandler.log wifi_ol ERROR \"$(msg)\",")
    puts("label no_recv_unknown_%s," % undot(host))
    
    # in-path counter resets
    puts("write ol_in_path_%s/all.reset," % undot(host))
    puts("write ol_in_path_%s/from_source.reset," % undot(host))
    puts("write ol_in_path_%s/unknown.reset," % undot(host))
    puts("write ol_in_path_%s/from_reroute.reset," % undot(host))
    puts("write ol_in_path_%s/ctrl.reset," % undot(host))

def create_wifioverlay_script(testbeds, coordinator, server):
    lines = []
    puts = lambda s: lines.append("        %s" % s)

    puts("set msg $(sprintf \"STATS host=%s recv=%s recv-bytes=%s\"")
    puts("    $(sys.hostname) $(ol_in_proxy.count) $(ol_in_proxy.byte_count)),")
    puts("write loghandler.log ol_in_proxy DATA \"$(msg)\",")
    puts("write ol_in_proxy.reset,")

    if not server:
        # stats from the (one) WifiOverlay element itself
        puts("set msg $(sprintf \"STATS host=%s routes=%s self-routes=%s no-route-pkts=%s unclassified=%s bcast-pkts=%s waitq-drops=%s waitq-drop-bytes=%s ttl-drops=%s ttl-drop-bytes=%s from-self-pkts=%s from-peers-pkts=%s\"")
        puts("    $(sys.hostname) $(wifi_ol.route_count) $(wifi_ol.assigned_bssids) $(wifi_ol.noroute_count)")
        puts("    $(ol_out_unclassified.count) $(ol_out_bcast_bssid.count) $(ol_waitq_drops.count) $(ol_waitq_drops.byte_count)")
        puts("    $(ol_ttl_drops.count) $(ol_ttl_drops.byte_count) $(ol_self_to_self.count) $(ol_net_to_self.count)),")
        puts("write loghandler.log wifi_ol INFO \"$(msg)\",")
        puts("write ol_out_unclassified.reset,")
        puts("write ol_out_bcast_bssid.reset,")
        puts("write ol_waitq_drops.reset,")
        puts("write ol_ttl_drops.reset,")
        puts("write ol_self_to_self.reset,")
        puts("write ol_net_to_self.reset,")

        # start with input/output stats to/from the coordinator itself
        append_peer_cmds(coordinator, lines)
        puts("")
        # then jump right to the section for our testbed (don't print stats for
        # peers that we will never send/recv messages with
        for testbed, hostnames in testbeds.iteritems():
            puts("goto %s_ol_stats $(in $(sys.hostname) %s)," % (testbed, " ".join(hostnames)))

    for testbed, hostnames in testbeds.iteritems():
        puts("label %s_ol_stats," % testbed)
        
        if server:
            # stats from the WifiOverlay element assigned to this testbed
            wifi_ol = "wifi_ol_%s" % testbed
            puts("set msg $(sprintf \"STATS host=%s routes=%s self-routes=%s\"")
            puts("    $(sys.hostname) $(%s.route_count) $(%s.assigned_bssids))," % \
                 (wifi_ol, wifi_ol))
            puts("write loghandler.log %s INFO \"$(msg)\"," % wifi_ol)

        # print input/output stats to/from each host in this testbed
        for host in hostnames:
            append_peer_cmds(host, lines)
            puts("")

        if not server:
            # skip stats for host belonging to other testbeds
            puts("goto done_ol_stats,")

    puts("label done_ol_stats,")
    
    return "\n".join(lines)

#
# MAIN
#
def main():
    parser = OptionParser(usage="%prog [options] DIR")
    (opts, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("expected exactly 1 argument")

    directory = args[0]
    coordinator = "www.citysense.net"  # hard-coded

    print "fetching node names from database..."
    argosroutes.initialize()

    # first do all outdoor nodes together as one unit
    testbeds = {}
    for testbed in argosroutes.get_outdoor_testbeds():
        testbeds[testbed] = argosroutes.get_nodes(testbed)

    print "starting to write files..."

    filename = os.path.join(args[0], "wifioverlay-node-outdoor.script")
    fi = open(filename, "w")
    print >>fi, create_wifioverlay_script(testbeds, coordinator, server=False)
    fi.close()
    print "created %s" % filename

    filename = os.path.join(args[0], "wifioverlay-server-outdoor.script")
    fi = open(filename, "w")
    print >>fi, create_wifioverlay_script(testbeds, coordinator, server=True)
    fi.close()
    print "created %s" % filename

    # next do all indoor (citymd) nodes
    testbeds = {"citymd": argosroutes.get_nodes("citymd") }

    filename = os.path.join(args[0], "wifioverlay-node-citymd.script")
    fi = open(filename, "w")
    print >>fi, create_wifioverlay_script(testbeds, coordinator, server=False)
    fi.close()
    print "created %s" % filename

    filename = os.path.join(args[0], "wifioverlay-server-citymd.script")
    fi = open(filename, "w")
    print >>fi, create_wifioverlay_script(testbeds, coordinator, server=True)
    fi.close()
    print "created %s" % filename

if __name__ == '__main__':
    main()
