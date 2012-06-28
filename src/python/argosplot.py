#!/usr/bin/env python

#
# IMPORTS
#

# system modules
import datetime
from optparse import OptionParser
import os
import re
import socket  # for address-to-hostname lookups
import sys
import time
import types
import warnings

# make matplotlib shut up
warnings.filterwarnings("ignore", "", DeprecationWarning, "matplotlib", 0)

# third-party modules
import matplotlib
matplotlib.use("Agg")  # must call this before importing matplotlib.pyplot
import matplotlib.pyplot as plot
from matplotlib.dates import DayLocator, HourLocator, MinuteLocator, \
     AutoDateFormatter, DateFormatter

# local modules
from dictify import dictify
import argoslog
import argosroutes


#
# GLOBAL CONSTANTS
#
METRIC_TYPE_PACKET_RATE=0  # a count of packets, best expressed as a rate
METRIC_TYPE_BYTE_RATE=1    # a count of bytes, best expressed as a rate
METRIC_TYPE_MEASURE=2      # a static measurement of some time-varying value
METRIC_TYPE_COUNT=3        # a count of some entity

AVAIL_METRICS = { "cpu": METRIC_TYPE_MEASURE,
                  "mem": METRIC_TYPE_MEASURE,
                  "mem-drops": METRIC_TYPE_PACKET_RATE,
                  "alloc-pkts": METRIC_TYPE_MEASURE,
                  "alloc-payloads": METRIC_TYPE_MEASURE,
                  "kern-recv": METRIC_TYPE_PACKET_RATE,
                  "kern-drops": METRIC_TYPE_PACKET_RATE,
                  "pcap-bytes": METRIC_TYPE_BYTE_RATE,
                  "pcap-pkts": METRIC_TYPE_PACKET_RATE,
                  "captured-bytes": METRIC_TYPE_BYTE_RATE,
                  "captured-pkts": METRIC_TYPE_PACKET_RATE,
                  "log-queue-drops": METRIC_TYPE_PACKET_RATE,
                  "pkt-queue-drops": METRIC_TYPE_PACKET_RATE,
                  "no-route-pkts": METRIC_TYPE_MEASURE,
                  "net": METRIC_TYPE_MEASURE,
                  "net-links": METRIC_TYPE_MEASURE,
                  "overlay-drops": METRIC_TYPE_PACKET_RATE,
                  "overlay-drop-bytes": METRIC_TYPE_BYTE_RATE,
                  "overlay-waitq-drops": METRIC_TYPE_PACKET_RATE,
                  "overlay-waitq-drop-bytes": METRIC_TYPE_BYTE_RATE,
                  "overlay-produced": METRIC_TYPE_PACKET_RATE,
                  "overlay-bytes-in": METRIC_TYPE_BYTE_RATE,
                  "overlay-bytes-out": METRIC_TYPE_BYTE_RATE,
                  "overlay-bytes-self": METRIC_TYPE_BYTE_RATE,
                  "overlay-pkts-in": METRIC_TYPE_PACKET_RATE,
                  "overlay-pkts-out": METRIC_TYPE_PACKET_RATE,
                  "overlay-pkts-self": METRIC_TYPE_PACKET_RATE,
                  "ol-waitq-drops": METRIC_TYPE_PACKET_RATE,
                  "to-server": METRIC_TYPE_BYTE_RATE,
                  "assigned-bssids": METRIC_TYPE_MEASURE,
                  "route-additions": METRIC_TYPE_COUNT,
                  "route-changes": METRIC_TYPE_COUNT,
                  "unaccounted-packets": METRIC_TYPE_MEASURE,
                  "merge-rate": METRIC_TYPE_MEASURE
                  }

# 40 = sizeof(struct argos_net_clickpkt), 48 = Packet::anno_size
OVERLAY_PACKET_HEADER=40
PACKET_ANNO_SIZE=48

# calculated from a trace
COMPRESSION_RATE=0.35

# values for publications figures
FIG_WIDTH=3.4   # inches
FIG_HEIGHT=2.4  # inches
DPI=72

DPI=72

INTERVAL=10

# enum for parse_overlay_traffic
OVERLAY_INCOMING=0
OVERLAY_OUTGOING=1
OVERLAY_SELF=2


#
# CLASSES
#
class NetworkData:
    def __init__(self, start):
        self.start_ts = time.mktime(start.timetuple())
        self.end_ts = time.mktime(start.timetuple())
        self.vals = {}

    def add_bytes(self, key, dt, b):
        ts = time.mktime(dt.timetuple())
        self.end_ts = max(self.end_ts, ts)
        self.vals[key] = self.vals.get(key, 0) + b

    def get_bytes(self, key):
        return self.vals.get(key, 0)

    def get_bitrate(self, key):
        return (self.vals.get(key, 0) * 8 / self.duration())

    def duration(self):
        d = self.end_ts - self.start_ts
        if d == 0:
            return 0.001
        else:
            return d

class ParseError(StandardError):
    def __init__(self, msg, entry):
        StandardError.__init__(self, msg)
        self.entry = entry

class Plotter:
    def __init__(self, metric, host_filter=None):
        self.metric = metric
        self.parser = get_parser(metric)
        self.hostmap = {}
        self.host_filter = host_filter

        metric_type = AVAIL_METRICS[self.metric]
        
        # some parsed values required some processing before they can be plotted
        # (e.g. converting from a raw count to a count-per-second average)
        if metric_type == METRIC_TYPE_PACKET_RATE:
            # these metrics are all better plotted as a per-second rate
            self.value_mult = 1/float(INTERVAL)
        
        elif metric_type == METRIC_TYPE_BYTE_RATE:
            # these metrics are all better plotted as a per-second rate, AND
            # need to be converted from bytes to Kbit/sec
            self.value_mult = 8/(1024*float(INTERVAL))
        
        elif metric_type == METRIC_TYPE_MEASURE:
            if self.metric == "mem":
                # special case: convert from KB to MB
                self.value_mult = 1/float(1024)
            else:
                # no processing necessary
                self.value_mult = 1
        elif metric_type == METRIC_TYPE_COUNT:
            # no processing necessary
            self.value_mult = 1
        else:
            raise ValueError("metric %s has bad type: %s" % (self.metric, metric_type))

    def parse_entry(self, entry):
        # initialize routes in case this is the first entry (ok to call more
        # than once - does nothing)
        argosroutes.initialize(entry.datetime)
        rv = self.parser(entry)

        for (host, val) in rv:
            if self.host_filter is not None:
                if host not in self.host_filter:
                    return
            else:
                # use default host filtering rule (which is "exclude 'citysense'
                # host from all plots except route additions & route changes
                if self.metric not in ["route-additions", "route-changes"]:
                    if host == "citysense":
                        return

            if self.metric in ["net", "net-links"]:
                # hostmap is a map from hostnames to NetworkData objects
                # val is a tuple: (overlay-bytes, mergestream-bytes, rawstream-bytes)
                if host not in self.hostmap:
                    self.hostmap[host] = NetworkData(entry.datetime)
                self.hostmap[host].add_bytes("overlay", entry.datetime, val[0])
                self.hostmap[host].add_bytes("mergestream", entry.datetime, val[1])
                self.hostmap[host].add_bytes("rawstream", entry.datetime, val[2])
            else:
                # hostmap is a map from hostnames to ScatterVals objects
                # val is a scalar (int or float)

                # perform any metric-specific processing of the value
                val = val*self.value_mult
                
                if host not in self.hostmap:
                    metric_type = AVAIL_METRICS[self.metric]
                    if metric_type == METRIC_TYPE_PACKET_RATE:
                        # packet rates should be added together
                        aggregate = sum
                    elif metric_type == METRIC_TYPE_BYTE_RATE:
                        # byte rates should be added together
                        aggregate = sum
                    elif metric_type == METRIC_TYPE_MEASURE:
                        # measurements should be averaged
                        aggregate = lambda li: sum(li)/len(li)
                    elif metric_type == METRIC_TYPE_COUNT:
                        # counts should be added together
                        aggregate = sum
                    else:
                        raise ValueError(metric_type)
                        
                    self.hostmap[host] = ScatterVals(60, aggregate)
                self.hostmap[host].putvals(entry.datetime, val)

    def show_marker(self):
        return (self.metric not in ["unaccounted-packets"])

class ScatterVals:
    def __init__(self, window, aggregate):
        self.x_vals = []
        self.y_vals = []
        self.win_vals = []
        self.win_start = None
        self.aggregate = aggregate

        if type(window) in [types.IntType, types.FloatType, types.LongType]:
            self.window = datetime.timedelta(seconds=window)
        else:
            # assume caller knows what he is doing
            self.window = window

    def putvals(self, x, y):
        if self.win_start is None:
            self.win_vals = [(x, y)]
            self.win_start = x
            return
        
        if x < self.win_start:
            raise ValueError("x (%s) < window-start (%s)" % \
                             (str(x), str(self.win_start)))

        if x >= (self.win_start + self.window):
            # time to collapse the current window of values into a single point
            pt_x = datetime_mean([v[0] for v in self.win_vals])
            pt_y = self.aggregate([v[1] for v in self.win_vals])
            self.x_vals.append(pt_x)
            self.y_vals.append(pt_y)
            self.win_vals = [(x, y)]
            self.win_start = x
        else:
            self.win_vals.append((x, y))

#
# METHODS
#
def datetime_mean(li):
    total = 0
    for dt in li:
        total += time.mktime(dt.timetuple()) + dt.microsecond/float(1000000)
    return datetime.datetime.fromtimestamp(total/len(li))
    
def estimate_network_bytes(bytes, pkts):
    headers = OVERLAY_PACKET_HEADER + PACKET_ANNO_SIZE
    return (bytes + pkts*headers)*COMPRESSION_RATE

def gen_bar_plot(plotter, outfile, format, size):
    if len(plotter.hostmap) == 0:
        return False
    
    fig = plot.figure(figsize=size)
    sp = fig.add_subplot(1,1,1)

    if plotter.metric not in ["net", "net-links"]:
        raise ValueError(plotter.metric)
    
    # sort hosts
    hosts = sorted(plotter.hostmap.keys())

    overlay_vals = []
    mergestream_vals = []
    rawstream_vals = []

    # plotter.hostmap is a map from hostnames to NetworkData objects
    for host in hosts:
        netdata = plotter.hostmap[host]
        overlay_vals.append(netdata.get_bitrate("overlay") / 1024)
        mergestream_vals.append(netdata.get_bitrate("mergestream") / 1024)
        rawstream_vals.append(netdata.get_bitrate("rawstream") / 1024)

    ind = range(len(plotter.hostmap))    # the x locations for the groups
    width = 0.25       # the width of the bars: can also be len(x) sequence

    p1 = plot.bar([x+0.22 for x in ind], mergestream_vals, width, color='b')
    p2 = plot.bar([x+0.22 for x in ind], overlay_vals, width, color='y',
                  bottom=mergestream_vals)
    p3 = plot.bar([x+0.53 for x in ind], rawstream_vals, width, color='g')

    plot.ylabel(get_yaxis_label(plotter.metric))
    plot.xticks([x+0.5 for x in ind], hosts)
    sp.set_xlim(0, ind[-1] + 1)

    # don't show actual ticks on x-axis (just labels)
    for l in sp.get_xticklines():
        l.set_markersize(0)

    # this works even though the x-labels are not dates
    fig.autofmt_xdate()  # align x-axis labels to be pretty

    # note - legend is not in 'plot-order' but it looks more natural this way
    sp.legend((p2[0], p1[0], p3[0]), \
              ("overlay traffic", "merged packets", "raw packets"),
              loc="lower right")

    plot.savefig(outfile, format=format, dpi=DPI)
    return True

def gen_timeseries_plot(plotter, outfile, format, size):
    if len(plotter.hostmap) == 0:
        return False
    
    fig = plot.figure(figsize=size)
    sp = fig.add_subplot(1,1,1)

    # sort hosts
    hosts = sorted(plotter.hostmap.keys())

    total_x_vals = 0
    min_x = None
    max_x = None

    # plotter.hostmap is a map from hostnames to ScatterVals objects
    for i in range(len(hosts)):
        host = hosts[i]
        data = plotter.hostmap[host]

        if len(data.x_vals) == 0:
            continue
        
        if total_x_vals == 0:
            min_x = min(data.x_vals)
            max_x = max(data.x_vals)
        else:
            min_x = min(min_x, min(data.x_vals))
            max_x = max(max_x, max(data.x_vals))

        if plotter.show_marker():
            marker = get_markerstyle(i)
        else:
            marker = ""

        sp.plot_date(data.x_vals, data.y_vals, label=host,
                     linestyle="-", marker=marker, color=get_color(i))

        total_x_vals += len(data.x_vals)

    # in some cases matplotlib seems to choke when there is only one datapoint
    if total_x_vals <= 1:
        return False

    span = max_x - min_x
    
    if span.days > 20:
        loc = DayLocator(bymonthday=[1,8,15,22,29])
    elif span.days > 7:
        loc = DayLocator()
    elif span.days > 1:
        loc = HourLocator(byhour=[0,4,8,12,16,20])
    elif span.seconds > 3*3600:
        loc = HourLocator()
    elif span.seconds > 15*60:
        loc = MinuteLocator(byminute=[0,15,30,45])
    else:
        loc = MinuteLocator()

    sp.xaxis.set_major_locator(loc)
    sp.xaxis.set_major_formatter(AutoDateFormatter(loc))
    sp.autoscale_view()
    sp.grid(True)

    fig.autofmt_xdate()  # align x-axis labels to be pretty

    plot.ylabel(get_yaxis_label(plotter.metric))
    leg = plot.legend()
    for l in leg.get_texts():
        l.set_fontsize(10)

    plot.savefig(outfile, format=format, dpi=DPI)
    return True

def get_color(i):
    colors = [ "red", "blue", "green", "magenta", "cyan", "yellow", "black" ]
    return colors[i % len(colors)]

def get_description(metric):
    if metric == "cpu":
        return "Percent CPU usage (usr + sys)"
    elif metric == "mem":
        return "Memory Utilization"
    elif metric == "mem-drops":
        return "Packet drops due to low memory (alloc failure)"
    elif metric == "alloc-pkts":
        return "allocated packets"
    elif metric == "alloc-payloads":
        return "allocated packet payloads"
    elif metric == "kern-recv":
        return "Packets received by kernel"
    elif metric == "kern-drops":
        return "Packets dropped by kernel"
    elif metric == "pcap-bytes":
        return "Bytes captured by libpcap (pre-filtering)"
    elif metric == "pcap-pkts":
        return "Packets captured by libpcap (pre-filtering)"
    elif metric == "captured-bytes":
        return "Bytes received by Click from the kernel"
    elif metric == "captured-pkts":
        return "Packets received by Click from the kernel"
    elif metric == "log-queue-drops":
        return "Log messages dropped by the running Click query"
    elif metric == "pkt-queue-drops":
        return "Packets dropped by the running Click query"
    elif metric == "no-route-pkts":
        return "Packets buffered while waiting for a route assignment"
    elif metric == "net":
        return "Summed network traffic by Node"
    elif metric == "net-links":
        return "Summed network traffic by network link"
    elif metric == "overlay-drops":
        return "Overlay packets dropped due to queue overflows"
    elif metric == "overlay-drop-bytes":
        return "Bytes of overlay packets dropped due to queue overflows"
    elif metric == "overlay-waitq-drop":
        return "Overlay packets dropped due to wait-queue overflows"
    elif metric == "overlay-waitq-drop-bytes":
        return "Bytes of overlay packets dropped due to wait-queue overflows"
    elif metric == "overlay-produced":
        return "Packets produced by the overlay (from the entire sniffer network)"
    elif metric.startswith("overlay-bytes-"):
        return "(description needed)"
    elif metric.startswith("overlay-pkts-"):
        return "(description needed)"
    elif metric == "to-server":
        return "Traffic to server imposed by the running Click query"
    elif metric == "assigned-bssids":
        return "Number of routes (BSSIDs) assigned to node"
    elif metric == "route-additions":
        return "New routes created"
    elif metric == "route-changes":
        return "Existing routes changed"
    elif metric == "unaccounted-packets":
        return "Packets that cannot be accounted for (possible bug)"
    elif metric == "merge-rate":
        return "WifiMerge's ratio of in-packets to out-packets"
    else:
        print "warning: unknown metric in get_description(): %s" % metric
        return None

def get_markerstyle(i):
    if i < 7:
        return "o"
    else:
        return "v"

# each parser should take a single LogEntry argument and return a 2-tuple of
# (hostname, value)
def get_parser(metric):
    if metric == "cpu":
        return (lambda e: parse_basic_line(e, "system", "SYSINFO", "cpu-10", float))
    
    elif metric == "mem":
        return (lambda e: parse_basic_line(e, "system", "SYSINFO", "maxrss-kb", float))
    
    elif metric == "mem-drops":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "mem-drop", strict=False))
    
    elif metric == "alloc-pkts":
        return (lambda e: parse_basic_line(e, "system", "SYSINFO", "alloc-pkts",
                                           lambda v: int(v.split("/")[0])))
    
    elif metric == "alloc-payloads":
        return (lambda e: parse_basic_line(e, "system", "SYSINFO", "alloc-pkts",
                                               lambda v: int(v.split("/")[0])))
    
    elif metric == "kern-recv":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "kern-recv"))
    
    elif metric == "kern-drops":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "kern-drop"))

    elif metric == "pcap-bytes":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "pre-capt-bytes"))

    elif metric == "pcap-pkts":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "pre-capt-pkts"))

    elif metric == "captured-bytes":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "post-capt-bytes"))

    elif metric == "captured-pkts":
        return (lambda e: parse_basic_line(e, "pcap", "STATS", "post-capt-pkts"))
    
    elif metric == "log-queue-drops":
        return (lambda e: parse_basic_line(e, "pcap", "APP-STATS", "log-qdrops"))
    
    elif metric == "pkt-queue-drops":
        return (lambda e: parse_basic_line(e, "pcap", "APP-STATS", "pkt-qdrops"))
    
    elif metric == "no-route-pkts":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "no-route-pkts"))
    
    elif metric == "net":
        return parse_net_usage
    
    elif metric == "net-links":
        return parse_net_links_usage

    elif metric == "overlay-drops":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "drops"))

    elif metric == "overlay-drop-bytes":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "drop-bytes", strict=False))

    elif metric == "overlay-waitq-drops":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "waitq-drops"))

    elif metric == "overlay-waitq-drop-bytes":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "waitq-drop-bytes", strict=False))

    elif metric == "overlay-produced":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "out-pkts"))

    elif metric == "overlay-bytes-in":
        return (lambda entry: parse_overlay_traffic(entry, as_packets=False,
                                                    kind=OVERLAY_INCOMING))
    
    elif metric == "overlay-bytes-out":
        return (lambda entry: parse_overlay_traffic(entry, as_packets=False,
                                                    kind=OVERLAY_OUTGOING))
        
    elif metric == "overlay-bytes-self":
        return (lambda entry: parse_overlay_traffic(entry, as_packets=False,
                                                    kind=OVERLAY_SELF))

    elif metric == "overlay-pkts-in":
        return (lambda entry: parse_overlay_traffic(entry, as_packets=True,
                                                    kind=OVERLAY_INCOMING))
        
    elif metric == "overlay-pkts-out":
        return (lambda entry: parse_overlay_traffic(entry, as_packets=True,
                                                    kind=OVERLAY_OUTGOING))
        
    elif metric == "overlay-pkts-self":
        return (lambda entry: parse_overlay_traffic(entry, as_packets=True,
                                                    kind=OVERLAY_SELF))

    elif metric == "ol-waitq-drops":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "waitq-drops"))
        
    elif metric == "to-server":
        return (lambda entry: parse_server_traffic(entry))
        
    elif metric == "assigned-bssids":
        return (lambda e: parse_basic_line(e, "wifi_ol", "STATS", "self-routes"))

    elif metric == "route-additions":
        # pass pattern as a parameter so that its only compiled once
        pat = re.compile("created (\d+) new routes; updated (\d+) routes")
        return (lambda entry: parse_route_stats(entry, pat, 1))

    elif metric == "route-changes":
        # pass pattern as a parameter so that its only compiled once
        pat = re.compile("created (\d+) new routes; updated (\d+) routes")
        return (lambda entry: parse_route_stats(entry, pat, 2))

    elif metric == "unaccounted-packets":
        counts = {}
        return (lambda entry: parse_unaccounted_packets(entry, counts))

    elif metric == "merge-rate":
        return (lambda entry: parse_merge_rate(entry))
    
    else:
        raise ValueError(metric)

def get_yaxis_label(metric):
    if metric == "cpu":
        return "perc. CPU utilization"
    elif metric == "mem":
        return "MB"
    elif metric == "mem-drops":
        return "packet / sec"
    elif metric == "alloc-pkts":
        return "allocated packets"
    elif metric == "alloc-payloads":
        return "allocated packet payloads"
    elif metric == "kern-recv":
        return "packets / sec"
    elif metric == "kern-drops":
        return "packets / sec"
    elif metric in ["pcap-bytes", "captured-bytes"]:
        return "Kbit/s"
    elif metric in ["pcap-pkts", "captured-pkts"]:
        return "packets / sec"
    elif metric == "log-queue-drops":
        return "messages / sec"
    elif metric == "pkt-queue-drops":
        return "packets / sec"
    elif metric == "no-route-pkts":
        return "unroutable (buffered) packets"
    elif metric == "net":
        return "network traffic (Kbit/s)"
    elif metric == "net-links":
        return "network traffic (Kbit/s)"
    elif metric == "overlay-drops":
        return "packets / sec"
    elif metric == "overlay-drop-bytes":
        return "Kbit/s"
    elif metric == "overlay-produced":
        return "packets / sec"
    elif metric.startswith("overlay-bytes-"):
        return "network traffic (Kbit/s)"
    elif metric.startswith("overlay-pkts-"):
        return "packets / sec (captured & control)"
    elif metric == "to-server":
        return "network traffic (Kbit/s)"
    elif metric == "assigned-bssids":
        return "# of BSSIDs (routes)"
    elif metric == "route-additions":
        return "# of route additions"
    elif metric == "route-changes":
        return "# of route changes"
    elif metric == "unaccounted-packets":
        return "packets"
    elif metric == "merge-rate":
        return "in:out ratio"
    else:
        print "warning: unknown metric in get_yaxis_label(): %s" % metric
        return metric

def parse_basic_line(entry, source_filter, head_filter, key, typecast=int, strict=True):
    if source_filter is not None:
        # LEGACY SUPPORT
        # in old versions, the 'pcap' source was named 'script', so if
        # source_filter="pcap", then check for either one
        if source_filter == "pcap":
            if entry.source not in [source_filter, "script"]:
                return []
        else:
            # normal check
            if entry.source != source_filter:
                return []

    # data format:
    # <FILTER> host=<hostname> <other fields>
    (head, _, tail) = entry.data.partition(" ")
    if head != head_filter:
        return []

    vals = dictify(tail)

    # also support old-style names that used underscores instead of dashes
    for k, v in vals.iteritems():
        if "_" in k:
            vals[k.replace("_", "-")] = v
            del vals[k]

    for field in ["host", key]:
        if field not in vals:
            if strict:
                print "bad line (no '%s' field): %s" % (field, entry)
            return []

    val = typecast(vals[key])
    host = argosroutes.to_hostname(vals["host"])    
    return [(host, val)]

def parse_merge_rate(entry):
    if entry.source != "wifi_merge":
        return []
    
    # data format:
    # <FILTER> host=<hostname> <other fields>
    (head, _, tail) = entry.data.partition(" ")
    if head != "STATS":
        return []

    vals = dictify(tail)

    for field in ["host", "avg_merge", "out_merges"]:
        if field not in vals:
            print "bad line (no '%s' field): %s" % (field, entry)
            return []

    if int(vals["out_merges"]) == 0:
        return []

    host = argosroutes.to_hostname(vals["host"])
    return [(host, float(vals["avg_merge"]))]

def parse_net_usage(entry):
    # list of (host, (overlay-bytes, mergestream-bytes, rawstream-bytes)) tuples
    data = []
    (head, _, tail) = entry.data.partition(" ")

    if entry.source in ["net_proxy", "to_server"]:
        # data format:
        # STATS host=[hostname] port=[port] count=X bytes=X
        if head == "STATS":
            # this tells us the number of bytes processed by the query running
            # on this node
            vals = dictify(tail)

            for field in ["host", "port", "bytes", "count"]:
                if field not in vals:
                    print "bad line (no '%s' field): %s" % (field, entry)
                    return []

            # the net_proxy logs multiple different lines, differentiated by the
            # 'port' field:
            # 'log' tracks log messages from the core system (not from queries)
            # 'stream' tracks packets streamed directly to the server
            # 'qX' tracks all NetworkProxy usage by query X
            # 'on_wire' tracks the (aggregate) data actually sent on the socket
            #  - note that this is post-compression whereas all of the other
            #  counts are pre-compression
            if vals["port"] != "on_wire":
                return []

            bytes = int(vals["bytes"])
            host = argosroutes.to_hostname(vals["host"])
    
            for (a, b) in argosroutes.walk_route(host, "citysense"):
                data.append((a, (0, bytes, 0)))
                data.append((b, (0, bytes, 0)))
    
    elif entry.source == "script":
        # data format:
        # STATS host=[hostname] kern_recv=X kern_drop=X pre_capt_pkts=X pre_capt_bytes=X
        #                       post_capt_pkts=X post_capt_bytes=X filter_pkts=X filter_bytes=X
        if head == "STATS":
            vals = dictify(tail)
            
            for field in ["host", "post_capt_bytes", "post_capt_pkts"]:
                if field not in vals:
                    print "bad line (no '%s' field): %s" % (field, entry)
                    return []

            # 'post_capt_bytes' field is bytes of packet, not network bytes
            bytes = estimate_network_bytes(int(vals["post_capt_bytes"]),
                                           int(vals["post_capt_pkts"]))
            host = argosroutes.to_hostname(vals["host"])

            for (a, b) in argosroutes.walk_route(host, "citysense"):
                data.append((a, (0, 0, bytes)))
                data.append((b, (0, 0, bytes)))

    elif entry.source == "wifi_ol":
        # data format:
        # NET-USAGE src=[ip] dst=[ip] capt_pkts=X capt_bytes=X | (repeat...)
        if head == "NET-USAGE":
            parts = tail.split("|")
            for part in parts:
                vals = dictify(part)

                for field in ["capt_bytes", "src", "dst"]:
                    if field not in vals:
                        print "bad line (no '%s' field): %s" % (field, entry)
                        return []
                
                # 'capt_bytes' field is actual network bytes, not just packet bytes
                bytes = int(vals["capt_bytes"])
                src = argosroutes.to_hostname(vals["src"])
                dst = argosroutes.to_hostname(vals["dst"])

                if src == dst:
                    # these are "self-routed" bytes which do not traverse the
                    # network at all
                    continue
                
                if bytes == 0:
                    continue

                if argosroutes.to_hostname(src) == "citysense":
                    # these should all be control messages, so we just ignore them
                    continue
                
                for (a, b) in argosroutes.walk_route(src, dst):
                    data.append((a, (bytes, 0, 0)))
                    data.append((b, (bytes, 0, 0)))

    return data

def parse_net_links_usage(entry):
    # list of (link, (overlay-bytes, mergestream-bytes, rawstream-bytes)) tuples
    data = []
    (head, _, tail) = entry.data.partition(" ")
    
    if entry.source in ["net_proxy", "to_server"]:
        # data format:
        # STATS host=[hostname] port=[port] count=X bytes=X
        if head == "STATS":
            # this tells us the number of bytes processed by the query running
            # on this node
            vals = dictify(tail)

            for field in ["host", "port", "bytes", "count"]:
                if field not in vals:
                    print "bad line (no '%s' field): %s" % (field, entry)
                    return []

            # the net_proxy logs multiple different lines, differentiated by the
            # 'port' field:
            # 'log' tracks log messages from the core system (not from queries)
            # 'stream' tracks packets streamed directly to the server
            # 'qX' tracks all NetworkProxy usage by query X
            # 'on_wire' tracks the (aggregate) data actually sent on the socket
            #  - note that this is post-compression whereas all of the other
            #  counts are pre-compression
            if vals["port"] != "on_wire":
                return []

            bytes = int(vals["bytes"])
            host = argosroutes.to_hostname(vals["host"])
    
            for link in argosroutes.walk_route(host, "citysense"):
                data.append((link, (0, bytes, 0)))
    
    elif entry.source == "script":
        # data format:
        # STATS host=[hostname] kern_recv=X kern_drop=X pre_capt_pkts=X pre_capt_bytes=X
        #                       post_capt_pkts=X post_capt_bytes=X filter_pkts=X filter_bytes=X
        if head == "STATS":
            vals = dictify(tail)
            
            for field in ["host", "post_capt_bytes", "post_capt_pkts"]:
                if field not in vals:
                    print "bad line (no '%s' field): %s" % (field, entry)
                    return []

            # 'post_capt_bytes' field is bytes of packets, not network bytes
            bytes = estimate_network_bytes(int(vals["post_capt_bytes"]),
                                           int(vals["post_capt_pkts"]))
            host = argosroutes.to_hostname(vals["host"])

            # 'link' is a (host,host) tuple
            for link in argosroutes.walk_route(host, "citysense"):
                data.append((link, (0, 0, bytes)))

    elif entry.source == "wifi_ol":        
        # data format:
        # NET-USAGE src=[ip] dst=[ip] capt_pkts=X capt_bytes=X | (repeat...)
        if head == "NET-USAGE":
            parts = tail.split("|")
            for part in parts:
                vals = dictify(part)

                for field in ["capt_bytes", "src", "dst"]:
                    if field not in vals:
                        print "bad line (no '%s' field): %s" % (field, entry)
                        return []
                
                # 'capt_bytes' field is actual network bytes, not just packet bytes
                bytes = int(vals["capt_bytes"])
                src = argosroutes.to_hostname(vals["src"])
                dst = argosroutes.to_hostname(vals["dst"])

                if src == dst:
                    # these are "self-routed" bytes which do not traverse the
                    # network at all
                    continue
                
                if bytes == 0:
                    continue

                if argosroutes.to_hostname(src) == "citysense":
                    # these should all be control messages, so we just ignore them
                    continue

                # 'link' is a (host,host) tuple
                for link in argosroutes.walk_route(src, dst):
                    data.append((link, (bytes, 0, 0)))

    return data

# returns a list of (host, peer, in-pkts, in-ctrl, in-bytes) tuples
def parse_overlay_instats(entry):
    if entry.source != "wifi_ol":
        return []

    # data format:
    # IN-STATS host=[hostname] peer=[hostname] in-pkts=X in-ctrl=X in-bytes=X
    (head, _, tail) = entry.data.partition(" ")
    if head != "IN-STATS":
        return []

    vals = dictify(tail)

    for field in ["host", "peer", "in-pkts", "in-ctrl", "in-bytes"]:
        if field not in vals:
            print "bad line (no '%s' field): %s" % (field, entry)
            return []

    host = argosroutes.to_hostname(vals["host"])
    return [ (host, vals["peer"], int(vals["in-pkts"]),
              int(vals["in-ctrl"]), int(vals["in-bytes"])) ]

# returns a list of (host, peer, queued-pkts, queued-ctrl, queued-bytes,
#   drop-pkts, drop-ctrl, drop-bytes, out-all, send-bytes) tuples
def parse_overlay_outstats(entry):
    if entry.source != "wifi_ol":
        return []

    # data format:
    # OUT-STATS host=[hostname] peer=[hostname] queued-pkts=X queued-ctrl=X
    #    queued-bytes=X drop-pkts=X drop-ctrl=X drop-bytes=X out-all=X send-bytes=X
    (head, _, tail) = entry.data.partition(" ")
    if head != "OUT-STATS":
        return []

    vals = dictify(tail)

    for field in ["host", "peer", "queued-pkts", "queued-ctrl", "queued-bytes",
                  "drop-pkts", "drop-ctrl", "drop-bytes", "out-all", "send-bytes"]:
        if field not in vals:
            print "bad line (no '%s' field): %s" % (field, entry)
            return []

    host = argosroutes.to_hostname(vals["host"])
    return [ (host, vals["peer"], int(vals["queued-pkts"]),
              int(vals["queued-ctrl"]), int(vals["queued-bytes"]),
              int(vals["drop-pkts"]), int(vals["drop-ctrl"]),
              int(vals["drop-bytes"]), int(vals["out-all"]),
              int(vals["send-bytes"]) ) ]                

def parse_route_stats(entry, pat, index):
    if entry.source != "wifi_ol":
        return []

    m = pat.match(entry.data)
    if m is None:
        return []
    else:
        return [("citysense", int(m.group(index)))]
    
def parse_server_traffic(entry):
    if entry.source not in ["net_proxy", "to_server"]:
        return []

    # data format:
    # STATS host=[hostname] port=[port] count=X bytes=X
    (head, _, tail) = entry.data.partition(" ")
    if head != "STATS":
        return []

    vals = dictify(tail)

    for field in ["host", "bytes", "count"]:
        if field not in vals:
            print "bad line (no '%s' field): %s" % (field, entry)
            return []

    bytes = estimate_network_bytes(int(vals["bytes"]), int(vals["count"]))

    host = argosroutes.to_hostname(vals["host"])
    return [(host, bytes)]

def parse_unaccounted_packets(entry, counts):
    hosts = set()
    
    p = get_parser("captured-pkts")
    for (host, val) in p(entry):
        counts[host] = counts.get(host, 0) + val
        hosts.add(host)

    p = get_parser("ol-waitq-drops")
    for (host, val) in p(entry):
        counts[host] = counts.get(host, 0) - val
        hosts.add(host)

    p = get_parser("overlay-drops")
    for (host, val) in p(entry):
        counts[host] = counts.get(host, 0) - val
        hosts.add(host)

    p = get_parser("overlay-produced")
    for (host, val) in p(entry):
        counts[host] = counts.get(host, 0) - val
        hosts.add(host)

    p = get_parser("overlay-pkts-in")
    for (host, val) in p(entry):
        counts[host] = counts.get(host, 0) + val
        hosts.add(host)

    p = get_parser("overlay-pkts-out")
    for (host, val) in p(entry):
        counts[host] = counts.get(host, 0) - val
        hosts.add(host)

    # TODO - can we subtract out the current queue lengths?

    li = []
    for host in hosts:
        li.append((host, counts[host]))
    return li


#
# MAIN
#
def main():
    parser = OptionParser(usage="%prog [options] [FILE] ...")
    parser.add_option("--hosts", help="filter by hosts")
    parser.add_option("-o", "--outfile", action="store", default=None,
                      help="Output file name")
    parser.add_option("--png", action="store_const", dest="format", const="png")
    parser.add_option("--eps", action="store_const", dest="format", const="eps")
    parser.add_option("--ps", action="store_const", dest="format", const="ps")
    parser.add_option("--pdf", action="store_const", dest="format", const="pdf")
    parser.add_option("--size", action="store", default="3.4x2.4",
                      help="Specify image size as NxM (in inches)")
    parser.add_option("--metric", action="store", type="choice",
                      choices=AVAIL_METRICS.keys(), default=None,
                      help="Which metric to parse and plot")
    parser.add_option("--list", action="store_true", default=False,
                      help="List all available metrics and quit")
    (opts, args) = parser.parse_args()

    if opts.list:
        for metric in sorted(AVAIL_METRICS.keys()):
            desc = get_description(metric)
            print "%s: %s" % (metric, desc)
        sys.exit(0)

    if opts.format is None:
        opts.format = "png"

    if opts.outfile is None:
        opts.outfile = "out.%s" % opts.format

    if opts.metric is None:
        parser.error("no metric selected")

    host_filter = None
    if opts.hosts:
        host_filter = set()
        for host in opts.hosts.split(","):
            host_filter.add(host)

    size = [float(x) for x in opts.size.split("x")]
    if len(size) != 2:
        parser.error("invalid size option (should be NxM)")

    print size

    plotter = Plotter(opts.metric, host_filter=host_filter)

    def print_err(e):
        print "parsing error: %s" % e

    if len(args) == 0:
        for entry in argoslog.parse(sys.stdin, errh=print_err):
            plotter.parse_entry(entry)
    else:
        for arg in args:
            fi = open(arg, "r")
            for entry in argoslog.parse(fi, errh=print_err):
                plotter.parse_entry(entry)
            fi.close()

    if plotter.metric in ["net", "net-links"]:
        created = gen_bar_plot(plotter, opts.outfile, opts.format, size)
    else:
        created = gen_timeseries_plot(plotter, opts.outfile, opts.format, size)

    if created:
        print "created %s" %  opts.outfile
    else:
        print "failed to create %s" % opts.outfile

if __name__ == '__main__':
    main()
