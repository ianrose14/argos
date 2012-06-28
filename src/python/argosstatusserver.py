#!/usr/bin/env python

#
# IMPORTS
#

# system modules
import BaseHTTPServer
import datetime
import re
import sys
import threading
import time
import traceback

# local modules
sys.path.append("lib/python")
import argoslog
import argosroutes
from dictify import dictify


#
# CLASSES
#

class HostInfo:
    def __init__(self, ts):
        self.up_since = ts
        self.last_msg = ts
        self.prior_uptime = 0
        self.disconnections = 0
        self.queries = {}
        self.channel_times = []
        self.message = None
        # cpu usage
        self.last_cpu_1 = 0
        self.last_cpu_10 = 0
        self.last_cpu_60 = 0
        self.last_cpu_all = 0
        # memory usage
        self.maxrss = 0
        self.wifimerge_mem = 0
        # ping performance
        self.ping_last_delay = 0
        self.ping_avg_delay = 0
        self.ping_recv = 0
        self.ping_drop = 0
        # pcap counts
        self.pcap_kern_recv = 0
        self.pcap_kern_drop = 0
        self.capt_pkts = 0   # post BSSID filtering
        self.capt_bytes = 0  # post BSSID filtering
        # wifi-overlay counts
        self.ol_pkts_in = 0
        self.ol_bytes_in = 0
        self.ol_pkts_out = 0
        self.ol_bytes_out = 0
        self.ol_pkts_drop = 0  # both captured packets and control messages
        # query-filter counts
        self.queries_pkts_in = 0
        self.queries_bytes_in = 0
        self.queries_pkts_drop = 0
        self.queries_bytes_drop = 0

    def is_down(self, now=None):
        if self.last_msg is None:
            return True
        if now is None:
            now = time.time()
        return ((now - self.last_msg) >= 60)

    def total_uptime(self):
        if self.up_since is None or self.last_msg is None:
            v = self.prior_uptime
        else:
            v = (self.last_msg - self.up_since) + self.prior_uptime

        # impose a minimum of 10 seconds just to avoid weird values when a node
        # has JUST started up and thus has a small (and inaccurate) uptime
        return max(v, 10)

    def update_uptime(self, ts):
        diff = ts - self.last_msg
        if diff >= 60:
            # assume there was a disconnection
            self.prior_uptime += (self.last_msg - self.up_since)
            self.up_since = ts
        self.last_msg = ts
    
class QueryInfo:
    def __init__(self):
        self.name = ""
        self.in_pkts = 0
        self.in_bytes = 0
        self.out_pkts = 0
        self.out_bytes = 0
        self.drop_pkts = 0

# shutdown() was added in Python v2.6 so we have to fake it ourselves
class ServerLooper:
    def __init__(self, server):
        self.server = server
        self.running = False

    def serve_forever(self, poll_interval=0.5):
        self.running = True
        import select
        poller = select.poll()
        poller.register(self.server.socket, select.POLLIN)
        while self.running:
            li = poller.poll(poll_interval*1000)
            if len(li) > 0:
                self.server.handle_request()

    def shutdown(self):
        self.running = False

# used by SystemStatusServer
class SystemStatusHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            content = self.server.writer.get_page_content(self.path)
            if content is None:
                self.send_error(404, "File not found")
            else:
                self.send_head()
                self.wfile.write(content)
        except StandardError:
            self.send_error(500, traceback.format_exc())

    def do_HEAD(self):
        try:
            content = self.server.writer.get_page_content(self.path)
            if content is None:
                self.send_error(404, "File not found")
            else:
                self.send_head()
        except StandardError:
            self.send_error(500, traceback.format_exc())

    def log_message(self, format, *args):
        pass  # don't log anything
            
    def send_head(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.end_headers()

class SystemStatusServer:
    SERVER_NAME = "citysense.net"
    
    def __init__(self, port):
        self.httpd = None
        self.port = port
        self.started = datetime.datetime.now()
        self.log_errors = []
        self.log_warnings = []
        self.hostinfo = {}
        self.exceptions = []  # exceptions raised in self.handle_log_entry()
        self.hostinfo[self.SERVER_NAME] = HostInfo(time.time())

    def __del__(self):
        if self.httpd is not None:
            self.stop()

    # called by instances of SystemStatusHandler
    def get_page_content(self, path):
        path, _, query = path.partition("?")
        
        title = "Argos System Status"  # default title
        if path == "/":
            content = self.get_index_content()
        elif path == "/details":
            if query.startswith("host="):
                hostname = query.partition("=")[2]
                info = self.hostinfo.get(hostname, None)
                if info is not None:
                    title = "Argos System Status: %s" % hostname
                    content = self.get_host_content(hostname, info)
                else:
                    content = "error: unknown host: %s" % hostname
            else:
                content = "error: no host specified"
        elif path == "/exceptions":
            content = "<hr>\n".join(["<pre>%s</pre>" % s for s in self.exceptions])
        else:
            return None  # 404 will be sent

        page = ["<html>",
                "<head><title>",
                title,
                "</title></head>",
                "<body>",
                content,
                "</body>",
                "</html>",
                ""]  # end with empty string so that page is newline-terminated
        
        return "\n".join(page)

    def get_host_content(self, hostname, info):
        now = time.time()
        dur = info.total_uptime()
        if dur == 0:
            dur = 0.0001  # dummy value
            
        content = []
        puts = lambda e: content.append(e)
        l = sorted(self.hostinfo.keys())
        i = l.index(hostname)
        if i == 0:
            prev_link = ""
        else:
            prev_link = "details?host=%s" % l[i-1]
        if i == (len(l)-1):
            next_link = ""
        else:
            next_link = "details?host=%s" % l[i+1]
        puts("<a href=\"/%s\">prev</a>&nbsp;&nbsp;&nbsp;" % prev_link)
        puts("<a href=\"/\">main page</a>&nbsp;&nbsp;&nbsp;")
        puts("<a href=\"/%s\">next</a>" % next_link)
        puts("<br>")
        puts("<h3>%s</h3>" % hostname)
        if info.last_msg is None:
            puts("status: unknown<br>")
        else:
            if info.is_down(now):
                downtime = format_time_str(now - info.last_msg)
                puts("status: <font color=\"red\">DOWN</font> (%s)<br>" % downtime)
            else:
                up_str = datetime.datetime.fromtimestamp(info.up_since)
                uptime = format_time_str(info.last_msg - info.up_since)
                puts("status: UP (%s, since: %s)<br>" % (uptime, up_str))
            puts("last message: %s ago (%s)<br>" % \
                 (format_time_str(now - info.last_msg),
                  datetime.datetime.fromtimestamp(info.last_msg)))
            
        puts("total uptime: %s<br>" % format_time_str(info.total_uptime()))
        puts("disconnections: %d<br>" % info.disconnections)
        puts("<hr>")

        # cpu usage
        puts("<table border=\"1\" cellpadding=\"2\">")
        puts("<tr><th>CPU-1</th><th>CPU-10</th><th>CPU-60</th><th>CPU-All</th></tr>")
        puts("<tr>")
        puts("<td align=\"center\">%s%%</td>" % (info.last_cpu_1*100))
        puts("<td align=\"center\">%s%%</td>" % (info.last_cpu_10*100))
        puts("<td align=\"center\">%s%%</td>" % (info.last_cpu_60*100))
        puts("<td align=\"center\">%s%%</td>" % (info.last_cpu_all*100))
        puts("</tr>")
        puts("</table>")

        # memory usage
        puts("&nbsp;")
        puts("<table border=\"1\" cellpadding=\"2\">")
        puts("<tr><th>Max RSS</th><th>WifiMerge Mem</th></tr>")
        puts("<tr>")
        puts("<td align=\"center\">%s</td>" % format_bytes_str(info.maxrss))
        puts("<td align=\"center\">%s</td>" % format_bytes_str(info.wifimerge_mem))
        puts("</tr>")
        puts("</table>")
        puts("<br>")

        # ping data
        puts("<table border=\"1\" cellpadding=\"2\">")
        puts("<tr><th>Cur Ping Delay</th><th>Avg Ping Delay</th><th>Drop Rate</th><th>Count</th></tr>")
        puts("<tr>")
        puts("<td align=\"center\">%s</td>" % format_time_str(info.ping_last_delay))
        puts("<td align=\"center\">%s</td>" % format_time_str(info.ping_avg_delay))
        total = info.ping_recv + info.ping_drop
        if total == 0:
            puts("<td align=\"center\">0%%</td>")
        else:
            puts("<td align=\"center\">%1.f%%</td>" % (info.ping_drop/float(total)))
        puts("<td align=\"center\">%d</td>" % info.ping_recv)
        puts("</tr>")
        puts("</table>")
        puts("<br>")

        # channel dwell times
        if len(info.channel_times) > 0:
            puts("<table border=\"1\" cellpadding=\"2\">")
            puts("<tr><th>Channel</th>")
            for i in range(len(info.channel_times)):
                puts("<td align=\"center\">%d</td>" % (i+1))
            puts("</tr>")
            puts("<tr><th>Share</th>")
            total_time = sum(info.channel_times)
            for i in range(len(info.channel_times)):
                sfont = ""
                efont = ""
                if total_time == 0:
                    perc = 0
                else:
                    perc = info.channel_times[i]/total_time
                    if perc < 0.05:
                        sfont = "<font color=\"#b0b0b0\">"
                        efont = "</font>"
                puts("<td>%s%.1f%%%s</td>" % (sfont, perc*100, efont))
            puts("</tr></table>")
            puts("<br>")
            
        # pcap counts
        puts("<table border=\"1\" cellpadding=\"2\">")
        puts("<tr><th>Kern Recv Pkts</th><th>Kern Drop Pkts</th><th>Capt Pkts</th><th>Capt Bytes</th></tr>")
        puts("<tr><td align=\"center\">%s (%s)</td>" % \
             (format_count_str(info.pcap_kern_recv), format_rate_str(info.pcap_kern_recv/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_count_str(info.pcap_kern_drop), format_rate_str(info.pcap_kern_drop/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_count_str(info.capt_pkts), format_rate_str(info.capt_pkts/dur)))
        puts("<td align=\"center\">%s (%s)</td></tr>" % \
             (format_bytes_str(info.capt_bytes), format_bitrate_str(info.capt_bytes*8/dur)))
        puts("</table>")
        puts("<br>")
        
        # query-filter counts
        puts("<table border=\"1\" cellpadding=\"2\">")
        puts("<tr>")
        puts("<th>Queries' Accepted Pkts</th>")
        puts("<th>Accepted Bytes</th>")
        puts("<th>Filtered Pkts</th>")
        puts("<th>Filtered Bytes</th>")
        puts("</tr>")
        puts("<tr>")
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_count_str(info.queries_pkts_in), format_rate_str(info.queries_pkts_in/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_bytes_str(info.queries_bytes_in), format_bitrate_str(info.queries_bytes_in*8/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_count_str(info.queries_pkts_drop), format_rate_str(info.queries_pkts_drop/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_bytes_str(info.queries_bytes_drop), format_bitrate_str(info.queries_bytes_drop*8/dur)))
        puts("</tr>")
        puts("</table>")
        puts("<br>")
        
        # wifi-overlay counts
        puts("<table border=\"1\" cellpadding=\"2\">")
        puts("<tr><th>Overlay Bytes In</th><th>Bytes Out</th><th>Pkts Out</th><th>Pkts Dropped</th></tr>")
        puts("<tr><td align=\"center\">%s (%s)</td>" % \
             (format_bytes_str(info.ol_bytes_in), format_bitrate_str(info.ol_bytes_in*8/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_bytes_str(info.ol_bytes_out), format_bitrate_str(info.ol_bytes_out*8/dur)))
        puts("<td align=\"center\">%s (%s)</td>" % \
             (format_count_str(info.ol_pkts_out), format_rate_str(info.ol_pkts_out/dur)))
        puts("<td align=\"center\">%s (%s)</td></tr>" % \
             (format_count_str(info.ol_pkts_drop), format_rate_str(info.ol_pkts_drop/dur)))
        puts("</table>")
        puts("<br>")
        
        puts("<table border=\"1\" padding=\"1\">")
        puts("<tr><th>Query ID</th><th>Name</th><th>In Packets</th><th>Out Packets</th><th>Out Bytes</th><th>Drops</th><th>Queue Len</th></tr>")
        
        putline = lambda iden, name, inp, outp, outb, drops, qlen: \
                  puts("<tr>" +
                       "<td>%s</td>" % iden +
                       "<td>%s</td>" % name +
                       "<td>%s (%s)</td>" % (format_count_str(inp), format_rate_str(inp/dur)) +
                       "<td>%s (%s)</td>" % (format_count_str(outp), format_rate_str(outp/dur)) +
                       "<td>%s (%s)</td>" % (format_bytes_str(outb), format_bitrate_str(outb*8/dur)) +
                       "<td>%s (%s)</td>" % (format_count_str(drops), format_rate_str(drops/dur)) +
                       "<td>%d</td>" % qlen +
                       "</tr>")
        
        for query_id in sorted(info.queries.keys()):
            query = info.queries[query_id]
            putline(query_id, query.name, query.in_pkts, query.out_pkts,
                    query.out_bytes, query.drop_pkts, query.qlen)
        
        total_in_pkts = sum([elt.in_pkts for elt in info.queries.values()])
        total_out_pkts = sum([elt.out_pkts for elt in info.queries.values()])
        total_out_bytes = sum([elt.out_bytes for elt in info.queries.values()])
        total_drop_pkts = sum([elt.drop_pkts for elt in info.queries.values()])
        total_qlen = sum([elt.qlen for elt in info.queries.values()])
        putline("", "(total)", total_in_pkts, total_out_pkts, total_out_bytes,
                total_drop_pkts, total_qlen)
        puts("</table>")
        return "\n".join(content)

    def get_index_content(self):
        content = []
        puts = lambda e: content.append(e)
        puts("system start: %s<br>" % self.started.ctime())
        puts("current time: %s<br>" % datetime.datetime.now().ctime())
        if len(self.exceptions) > 0:
            puts("<b><font color=\"red\">server exceptions: %d</font></b>  <a href=\"exceptions\">view</a><br>" % \
                 len(self.exceptions))
        puts("<br>")
        puts("<b>total hosts: %d</b>" % len(self.hostinfo))
        puts("<b>online hosts: %d</b>" % \
             len([elt for elt in self.hostinfo.values() if not elt.is_down()]))
        puts("<table border=\"1\" padding=\"1\">")
        puts("<tr>")
        puts("<th>Host</th>")
        puts("<th>Total Uptime</th>")
        puts("<th>Down Since</th>")
        puts("<th>Disconnections</th>")
        puts("<th>CPU-All</th>")
        puts("<th>Max RSS</th>")
        puts("<th>Capture</th>")
        puts("<th>Overlay</th>")
        puts("</tr>")
        for hostname in sorted(self.hostinfo.keys()):
            info = self.hostinfo[hostname]
            dur = info.total_uptime()
            if dur == 0:
                dur = 0.0001  # dummy value
            down_str = ""
            if info.is_down() and info.last_msg is not None:
                down_str = datetime.datetime.fromtimestamp(info.last_msg)

            puts("<tr>")
            puts("<td align=\"center\"><tt><a href=\"details?host=%s\">%s</a></tt></td>" % (hostname, hostname))
            puts("<td align=\"center\">%s</td>" % fixedw(format_time_str(info.total_uptime()), 10))
            puts("<td align=\"center\"><font color=\"red\">%s</font></td>" % fixedw(down_str))
            puts("<td align=\"center\">%s</td>" % fixedw(info.disconnections, 4))
            puts("<td align=\"center\">%s</td>" % fixedw("%4s%%" % str(info.last_cpu_all*100)))
            puts("<td align=\"center\">%s</td>" % fixedw(format_bytes_str(info.maxrss)))
            puts("<td align=\"center\">%s</td>" % fixedw(format_rate_str(info.capt_pkts/dur), 5))
            if info.ol_pkts_drop > 0:
                sfont = "<span style=\"color: red\">"
                efont = "</span>"
            else:
                sfont = ""
                efont = ""
            puts("<td align=\"center\">%s</td></tr>" % \
                 fixedw("%10s in, %10s out, %s%5s drop%s" %
                        (format_bitrate_str(info.ol_bytes_in*8/dur),
                         format_bitrate_str(info.ol_bytes_out*8/dur),
                         sfont, format_rate_str(info.ol_pkts_drop/dur), efont)))
            puts("</tr>")
        puts("</table>")
        puts("<br>")
        
        puts("<hr>")
        puts("<b><font color=\"red\">Web-Server Messages</font></b><br>")
        puts("<br>")
        for hostname in sorted(self.hostinfo.keys()):
            info = self.hostinfo[hostname]
            if info.message is not None:
                puts("%s: %s<br>" % (hostname, info.message))
        puts("<br>")
        
        puts("<hr>")
        puts("<b><font color=\"red\">ERRORS</font></b><br>")
        puts("<br>")
        # print most-recent first
        i = 0
        for entry in reversed(self.log_errors):
            if i > 100:
                puts("(list truncated)<br>")
                break
            puts("%s<br>" % str(entry))
            i += 1
        puts("<br>")
        
        puts("<hr>")
        puts("<b><font color=\"red\">WARNINGS</font></b><br>")
        puts("<br>")
        # print most-recent first
        i = 0
        for entry in reversed(self.log_warnings):
            if i > 100:
                puts("(list truncated)<br>")
                break
            puts("%s<br>" % str(entry))
            i += 1
        return "\n".join(content)

    def handle_channel_entry(self, entry):
        # example: DATA  host=citymd001 0: 0.000000, 1: 0.641331, 2: 0.000000, 3: 0.000000, 4: 0.000000, 5: 0.000000, 6: 0.000000, 7: 1.844721, 8: 1.987362, 9: 1.986150, 10: 1.985775, 11: 2.405495
        vals = dictify(entry.data)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)

        for key, value in vals.iteritems():
            if key[0] != "c":
                continue
            channel = int(key[1:])
            if channel < 1:
                continue
            while channel > len(info.channel_times):
                info.channel_times.append(0)
            info.channel_times[channel-1] += float(value)

    def handle_ctrlserver_entry(self, entry):
        # example: connection closed to citysense003-mgmt (192.168.144.3) on fd 23
        m = re.match("connection closed to (.+)", entry.data)
        if m is not None:
            hostname = m.group(1)
            hostname = self.normalize_hostname(hostname)
            # do not create entries for new hosts and do not update hosts' uptimes
            info = self.lookup_host(hostname, entry, create=False)
            if info is not None:
                info.disconnections += 1

    # just dispatches to other handle_xxx_entry() methods
    def handle_log_entry(self, entry):
        try:
            if entry.loglevel == argoslog.LOG_ERR:
                self.log_errors.append(entry)
            elif entry.loglevel == argoslog.LOG_WARN:
                self.log_warnings.append(entry)
            elif entry.loglevel in [argoslog.LOG_DATA, argoslog.LOG_INFO]:
                if entry.source == "chan_mgr":
                    self.handle_channel_entry(entry)
                elif entry.source == "ctrl_server":
                    self.handle_ctrlserver_entry(entry)
                elif entry.source == "queries":
                    self.handle_queries_entry(entry)
                elif entry.source == "queryfilt":
                    self.handle_queryfilt_entry(entry)
                elif entry.source == "pcap":
                    self.handle_pcap_entry(entry)
                elif entry.source == "pings":
                    self.handle_pings_entry(entry)
                elif entry.source == "system":
                    self.handle_sysinfo_entry(entry)
                elif entry.source == "ol_in_proxy":
                    self.handle_olinproxy_entry(entry)
                elif entry.source == "wifi_merge":
                    self.handle_wifimerge_entry(entry)
                elif entry.source[:7] == "wifi_ol":
                    self.handle_wifiol_entry(entry)
        except StandardError, e:
            if len(self.exceptions) < 100:
                self.exceptions.append(traceback.format_exc())

    def handle_olinproxy_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "STATS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        info.ol_pkts_in += int(vals["recv"])
        info.ol_bytes_in += int(vals["recv-bytes"])

    def handle_pcap_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "STATS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        info.pcap_kern_recv += int(vals["kern-recv"])
        info.pcap_kern_drop += int(vals["kern-drop"])
        info.capt_pkts += int(vals["post-capt-pkts"])
        info.capt_bytes += int(vals["post-capt-bytes"])

    def handle_pings_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "STATS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        if hostname != self.SERVER_NAME:
            return
        peername = self.normalize_hostname(vals["peer"])
        # do not create entries for new hosts and do not update hosts' uptimes
        info = self.lookup_host(peername, entry, create=False)
        if info is None:
            return
        info.ping_last_delay = entry.timestamp - float(vals["last-ping"])
        info.ping_avg_delay = float(vals["avg-delay-ms"])/1000
        info.ping_recv += int(vals["count"])
        info.ping_drop += int(vals["drops"])

    def handle_queries_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "STATS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        query_id = vals["id"]
        if query_id not in info.queries:
            info.queries[query_id] = QueryInfo()
        query = info.queries[query_id]
        query.name = vals["query"]
        query.in_pkts += int(vals["in-pkts"])
        query.out_pkts += int(vals["out-pkts"])
        query.out_bytes += int(vals["out-bytes"])
        query.drop_pkts += int(vals["drop-pkts"])
        query.qlen = int(vals["qlen"])

    def handle_queryfilt_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "STATS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        info.queries_pkts_in += int(vals["accepted-pkts"])
        info.queries_bytes_in += int(vals["accepted-bytes"])
        info.queries_pkts_drop += int(vals["filtered-pkts"])
        info.queries_bytes_drop += int(vals["filtered-bytes"])
        
    def handle_sysinfo_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "SYSINFO":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        info.maxrss = int(vals["maxrss-kb"])*1024
        info.last_cpu_1 = float(vals["cpu-1"])
        info.last_cpu_10 = float(vals["cpu-10"])
        info.last_cpu_60 = float(vals["cpu-60"])
        info.last_cpu_all = float(vals["cpu-all"])

    def handle_wifimerge_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "STATUS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        info.wifimerge_mem = int(vals["mem"])

    def handle_wifiol_entry(self, entry):
        (head, _, tail) = entry.data.partition(" ")
        if head != "OUT-STATS":
            return
        vals = dictify(tail)
        hostname = self.normalize_hostname(vals["host"])
        info = self.lookup_host(hostname, entry)
        info.update_uptime(entry.timestamp)
        info.ol_pkts_out += int(vals["out-all"])
        info.ol_bytes_out += int(vals["send-bytes"])
        info.ol_pkts_drop += int(vals["drop-pkts"]) + int(vals["drop-ctrl"])

    def lookup_host(self, hostname, entry, create=True):
        if hostname not in self.hostinfo:
            if not create:
                return None
            self.hostinfo[hostname] = HostInfo(entry.timestamp)
            info = self.hostinfo.get(hostname)
        else:
            info = self.hostinfo.get(hostname)
        return info

    def normalize_hostname(self, hostname):
        try:
            hostname = argosroutes.to_hostname(hostname)
        except ValueError:
            pass
        hostname = hostname.split("-")[0]
        if hostname in ["citysense", "citysense.eecs.harvard.edu", "www.citysense.net"]:
            hostname = self.SERVER_NAME
        return hostname

    def start(self):
        # create a new thread which will run the http server
        addr = ("", self.port)
        server = BaseHTTPServer.HTTPServer(addr, SystemStatusHandler)
        # each SystemStatusHandler object needs a handle to (self) so that it
        # can grab the content it needs to render a page, so pass a reference to
        # ourselves via the server object (which Handlers have a reference to)
        server.writer = self
        self.httpd = ServerLooper(server)
        self.httpd_thread = threading.Thread(target=self.httpd.serve_forever)
        self.httpd_thread.start()

    def stop(self):
        self.httpd.shutdown()  # tells the serve_forever() loop to stop
        self.httpd_thread.join(5)
        if self.httpd_thread.isAlive():
            raise StandardError("httpd_thread failed to join after 5 sec")

#
# METHODS
#
def format_bitrate_str(bitrate):
    bitrate = float(bitrate)
    if bitrate < 1024:
        return "%.0f bits/s" % bitrate
    elif bitrate < (1024**2):
        return "%.0f Kb/s" % (bitrate/1024)
    else:
        return "%.1f Mb/s" % (bitrate/(1024**2))

def format_bytes_str(bytes):
    bytes = float(bytes)
    if bytes < 1024:
        return str(bytes)
    elif bytes < 10*1024:
        return "%.1f KB" % (bytes/1024)
    elif bytes < 1024**2:
        return "%.0f KB" % (bytes/1024)
    elif bytes < 10*(1024**2):
        return "%.1f MB" % (bytes/(1024**2))
    elif bytes < 1024**3:
        return "%.0f MB" % (bytes/(1024**2))
    elif bytes < 10*(1024**3):
        return "%.1f GB" % (bytes/(1024**3))
    elif bytes < 1024**4:
        return "%.0f GB" % (bytes/(1024**3))
    elif bytes < 10*(1024**4):
        return "%.1f TB" % (bytes/(1024**4))
    else:
        return "%.0f TB" % (bytes/(1024**4))

def format_count_str(c):
    c = float(c)
    if c < 1000:
        return str(c)
    elif c < 10*1000:
        return "%.1fK" % (c/1000)
    elif c < 1000**2:
        return "%.0fK" % (c/1000)
    elif c < 10*(1000**2):
        return "%.1fM" % (c/(1000**2))
    elif c < 1000**3:
        return "%.0fM" % (c/(1000**2))
    elif c < 10*(1000**3):
        return "%.1fB" % (c/(1000**3))
    elif c < 1000**4:
        return "%.0fB" % (c/(1000**3))
    elif c < 10*(1000**4):
        return "%.1fT" % (c/(1000**4))
    else:
        return "%.0fT" % (c/(1000**4))

def format_rate_str(c):
    c = float(c)
    if c == 0:
        return "0/s"
    elif c < 1:
        return "%.2f/s" % c
    elif c < 10:
        return "%.1f/s" % c
    elif c < 1000:
        return "%.0f/s" % c
    elif c < 10*1000:
        return "%.1f K/s" % (c/1000)
    elif c < 1000**2:
        return "%.0fK/s" % (c/1000)
    elif c < 10*(1000**2):
        return "%.1fM/s" % (c/(1000**2))
    elif c < 1000**3:
        return "%.0fM/s" % (c/(1000**2))
    elif c < 10*(1000**3):
        return "%.1fB/s" % (c/(1000**3))
    elif c < 1000**4:
        return "%.0fB/s" % (c/(1000**3))
    elif c < 10*(1000**4):
        return "%.1fT/s" % (c/(1000**4))
    else:
        return "%.0fT/s" % (c/(1000**4))

def format_time_str(seconds):
    seconds = float(seconds)
    if seconds == 0:
        return "0 sec"
    elif seconds < 0.001:
        return "%.0f usec" % (seconds*1000*1000)
    elif seconds < 0.002:
        return "%.2f msec" % (seconds*1000)
    elif seconds < 1:
        return "%.0f msec" % (seconds*1000)
    elif seconds < 5:
        return "%.2f sec" % seconds
    elif seconds < 60:
        return "%.0f sec" % seconds
    elif seconds < 2*60:
        return "%.1f min" % (seconds/60)
    elif seconds < 3600:
        return "%.0f min" % (seconds/60)
    elif seconds < 7200:
        return "%.1f hrs" % (seconds/3600)
    elif seconds < (2*24*3600):
        return "%.0f hours" % (seconds/3600)
    else:
        return "%.1f days" % (seconds/(24*3600))

def fixedw(s, length=None):
    s = str(s)
    if length is not None:
        fmt = "%%%ds" % length
        s = fmt % s
    return "<tt>%s</tt>" % s.replace(" ", "&nbsp;")
