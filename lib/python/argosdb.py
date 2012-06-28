#!/usr/local/bin/python

#
# IMPORTS
#

# system modules
from optparse import OptionParser
import sys
import time

# third-party modules
import psycopg2
import psycopg2.extensions

# local modules
from dictify import dictify
import argoslog


#
# CLASSES
#

class ArgosDB:
    def __init__(self, username, password, dbname, host=None, debug=False):
        if host is None:
            connstr = "user=%s password=%s dbname=%s" % (username, password, dbname)
        else:
            connstr = "host=%s user=%s password=%s dbname=%s" % (host, username, password, dbname)

        self.debug = debug
        self.conn = None
        self.cur = None

        if self.debug:
            print "connecting..."
        self.conn = psycopg2.connect(connstr)
        # for now, commit on every execution
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        self.cur = self.conn.cursor()

    def close(self, commit=False):
        if commit:
            self.commit()
            
        if self.cur is not None:
            self.cur.close()
            self.cur = None
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def commit(self):
        if self.debug:
            print "committing..."
        try:
            self.conn.commit()
        except psycopg2.Error, e:
            self.cur.close()
            self.cur = None
            raise e

    def execute(self, cmd, args):
        if self.cur is None:
            self.cur = self.conn.cursor()

        if self.debug:
            print "executing: %s" % cmd

        try:
            self.cur.execute(cmd, args)
        except psycopg2.Error, e:
            self.cur.close()
            self.cur = None
            raise e

class Parser:
    def __init__(self, db):
        self.db = db
        self.default_duration = 10  # seconds

        # all indexed by node_id
        self.last_pcap_stats = {}
        self.last_query_stats = {}
        self.last_toserver_stats = {}
        self.last_toserver_out_stats = {}
        self.last_wifi_ol_sniffer_stats = {}
        self.last_wifi_ol_server_stats = {}
        self.last_wifi_ol_inproxy_stats = {}
        self.last_wifi_ol_in_stats = {}
        self.last_wifi_ol_out_stats = {}

    def parse_entry(self, entry):
        try:
            if entry.source == "ol_in_proxy":
                (head, _, tail) = entry.data.partition(" ")
                if head == "STATS":
                    self.parse_wifi_ol_inproxy_stats(entry.datetime, dictify(tail))
                    
            elif entry.source == "pcap":
                (head, _, tail) = entry.data.partition(" ")
                if head == "STATS":
                    self.parse_pcap_stats(entry.datetime, dictify(tail))

            elif entry.source == "queries":
                (head, _, tail) = entry.data.partition(" ")
                if head == "STATS":
                    self.parse_query_stats(entry.datetime, dictify(tail))
            
            elif entry.source == "to_server":
                (head, _, tail) = entry.data.partition(" ")
                if head == "STATS":
                    self.parse_toserver_stats(entry.datetime, dictify(tail))
                elif head == "OUT-STATS":
                    self.parse_toserver_out_stats(entry.datetime, dictify(tail))
                
            # special case: all 'wifi_ol_xxx' sources count as the same source
            # a quick test shows slicing is faster than startswith()
            elif entry.source[:7] == "wifi_ol":
                (head, _, tail) = entry.data.partition(" ")
                if head == "STATS":
                    # faster version of "if entry.source == 'wifi_ol'"
                    if len(entry.source) == 7:
                        # this is from a node...
                        self.parse_wifi_ol_sniffer_stats(entry.datetime, dictify(tail))
                    else:
                        # this is from the server...
                        self.parse_wifi_ol_server_stats(entry.datetime, dictify(tail), entry.source[8:])
                elif head == "IN-STATS":
                    self.parse_wifi_ol_in_stats(entry.datetime, dictify(tail))
                elif head == "OUT-STATS":
                    self.parse_wifi_ol_out_stats(entry.datetime, dictify(tail))
                    
        except KeyError, e:
            raise ValueError("field '%s' not found" % e.args[0])

    def parse_line(self, line):
        entry = argoslog.parse_line(line)
        if entry is not None:
            self.parse_entry(entry)

    def parse_pcap_stats(self, dt, vals):
        query = "insert into pcap_stats (timestamp, duration_msec, node_id, kernel_recv, kernel_drop, mem_drop, all_capt_packets, all_capt_bytes, filt_capt_packets, filt_capt_bytes) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"

        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])
        
        last_time = self.last_pcap_stats.get(node_id, None)
        self.last_pcap_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
            
        args = (dt, dur*1000, node_id, vals["kern-recv"], vals["kern-drop"], \
                vals["mem-drop"], vals["pre-capt-pkts"], vals["pre-capt-bytes"], \
                vals["post-capt-pkts"], vals["post-capt-bytes"])
        self.db.execute(query, args)

    def parse_query_stats(self, dt, vals):
        query = "insert into query_stats (timestamp, duration_msec, node_id, query, in_packets, out_msgs, out_bytes, dropped_msgs) values (%s, %s, %s, %s, %s, %s, %s, %s);"

        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])
        queryname = vals["query"]
        key = (node_id, queryname)  # unlike most parsers, the key is not just node_id

        last_time = self.last_query_stats.get(key, None)
        self.last_query_stats[key] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        args = (dt, dur*1000, node_id, queryname, vals["in-pkts"], vals["out-pkts"], vals["out-bytes"], vals["drop-pkts"])
        self.db.execute(query, args)
        
    def parse_toserver_stats(self, dt, vals):
        query = "insert into toserver_query_stats (timestamp, duration_msec, node_id, query, dequeued_msgs, dequeued_bytes) values (%s, %s, %s, %s, %s, %s);"

        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_toserver_stats.get(node_id, None)
        self.last_toserver_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        args = (dt, dur*1000, node_id, vals["query"], vals["count"], vals["bytes"])
        self.db.execute(query, args)

    def parse_toserver_out_stats(self, dt, vals):
        query = "insert into toserver_output_stats (timestamp, duration_msec, node_id, sent_msgs, sent_bytes, compress_rate, avg_compress_size, avg_cpu) values (%s, %s, %s, %s, %s, %s, %s, %s);"
    
        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_toserver_out_stats.get(node_id, None)
        self.last_toserver_out_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        args = (dt, dur*1000, node_id, vals["count"], vals["bytes"], vals["avg-compress-rate"], vals["avg-compress-size"], vals["avg-cpu"])
        self.db.execute(query, args)

    def parse_wifi_ol_sniffer_stats(self, dt, vals):
        query = "insert into overlay_sniffer_stats (timestamp, duration_msec, node_id, total_routes, self_routes, no_route_packets, unclassified_packets, bcast_packets, waitq_dropped_msgs, waitq_dropped_bytes, ttl_dropped_msgs, ttl_dropped_bytes, from_self_packets, from_peers_packets, net_recv_msgs, net_recv_bytes) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"
        
        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_wifi_ol_sniffer_stats.get(node_id, None)
        self.last_wifi_ol_sniffer_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        args = (dt, dur*1000, node_id, vals["routes"], vals["self-routes"], vals["no-route-pkts"], vals["unclassified"], vals["bcast-pkts"], vals["waitq-drops"], vals["waitq-drop-bytes"], vals["ttl-drops"], vals["ttl-drop-bytes"], vals["from-self-pkts"], vals["from-peers-pkts"], vals["recv"], vals["recv-bytes"])
        self.db.execute(query, args)
    
    def parse_wifi_ol_server_stats(self, dt, vals, testbed):
        query = "insert into overlay_server_stats (timestamp, duration_msec, node_id, testbed, total_routes) values (%s, %s, %s, %s, %s);"
        
        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_wifi_ol_server_stats.get(node_id, None)
        self.last_wifi_ol_server_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        args = (dt, dur*1000, node_id, testbed, vals["routes"])
        self.db.execute(query, args)
    
    def parse_wifi_ol_inproxy_stats(self, dt, vals):
        query = "insert into overlay_server_sockrecv (timestamp, duration_msec, node_id, net_recv_msgs, net_recv_bytes) values (%s, %s, %s, %s, %s);"
        
        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_wifi_ol_inproxy_stats.get(node_id, None)
        self.last_wifi_ol_inproxy_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        args = (dt, dur*1000, node_id, vals["recv"], vals["recv-bytes"])
        self.db.execute(query, args)
    
    def parse_wifi_ol_in_stats(self, dt, vals):
        query = "insert into overlay_peer_input_stats (timestamp, duration_msec, node_id, peer_node_id, recv_packets, recv_ctrl_msgs, recv_bytes) values (%s, %s, %s, %s, %s, %s, %s);"
        
        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_wifi_ol_in_stats.get(node_id, None)
        self.last_wifi_ol_in_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        peer_node_id = get_node_id(vals["peer"])
        args = (dt, dur*1000, node_id, peer_node_id, vals["in-pkts"], vals["in-ctrl"], vals["in-bytes"])
        self.db.execute(query, args)
    
    def parse_wifi_ol_out_stats(self, dt, vals):
        query = "insert into overlay_peer_output_stats (timestamp, duration_msec, node_id, peer_node_id, enqueued_packets, enqueued_ctrl_msgs, enqueued_bytes, enqueued_reroute_msgs, dropped_packets, dropped_ctrl_msgs, dropped_bytes, dequeued_msgs, sent_bytes, compress_rate, avg_compress_size, avg_cpu) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"
        
        ts = datetime_to_ts(dt)
        node_id = get_node_id(vals["host"])

        last_time = self.last_wifi_ol_out_stats.get(node_id, None)
        self.last_wifi_ol_out_stats[node_id] = ts
        if last_time is None:
            dur = self.default_duration
        else:
            dur = ts - last_time
        
        peer_node_id = get_node_id(vals["peer"])
        args = (dt, dur*1000, node_id, peer_node_id, vals["queued-pkts"], vals["queued-ctrl"], vals["queued-bytes"], vals["queued-reroutes"], vals["drop-pkts"], vals["drop-ctrl"], vals["drop-bytes"], vals["out-all"], vals["send-bytes"], vals["compress-rate"], vals["avg-compress-size"], vals["avg-cpu"])
        self.db.execute(query, args)


#
# METHODS
#
def datetime_to_ts(dt):
    return time.mktime(dt.timetuple()) + float(dt.microsecond)/1000000

def get_node_id(hostname):
    if hostname == "www.citysense.net":
        return 0
    if hostname[:9] == "citysense":
        if hostname == "citysense.eecs.harvard.edu":
            return 0
        try:
            return int(hostname[9:])
        except ValueError:
            raise ValueError(hostname)
    if hostname[:6] == "citymd":
        return -1*int(hostname[6:])
    raise ValueError(hostname)


#
# Main
#
def main():
    parser = OptionParser(usage="%prog [options] USERNAME PASSWORD DBNAME")
    parser.add_option("-v", "--verbose", action="count", default=0)
    (opts, args) = parser.parse_args()

    if len(args) != 3:
        parser.error("wrong number of arguments")

    (username, password, dbname) = args
    db = ArgosDB(username, password, dbname, debug=(opts.verbose > 0))

    parser = Parser(db)

    c = 0
    for entry in argoslog.parse(sys.stdin, window=0):
        if parser.parse_entry(entry):
            c += 1
            if opts.verbose > 0:
                print "accepted: %s" % str(entry)
        else:
            if opts.verbose > 1:
                print "rejected: %s" % str(entry)

    print "%d entries accepted" % c

if __name__ == '__main__':
    main()
