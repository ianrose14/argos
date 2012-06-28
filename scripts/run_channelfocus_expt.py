#!/usr/bin/env python

#
# IMPORTS
#

# system modules
from optparse import OptionParser
import os
import signal
import sys
import tempfile
import time

# local modules
sys.path.append("lib/python")
import argos
import run_queries


#
# MAIN
#
def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    parser = OptionParser(usage="%prog [options] -c FILE")
    parser.add_option("-c", "--config", action="store",
                      help="Argos config file")
    parser.add_option("-o", "--outdir", metavar="FILE",
                      help="Write output to logs in named directory")
    parser.add_option("-p", "--port", type="int", help="Specify control port")
    parser.add_option("--run", type="int", default=1)
    parser.add_option("--dump", default=False, action="store_true",
                      help="Don't execute click; just output configuration")
    parser.add_option("--dump-node", default=False, action="store_true",
                      help="Don't execute click; just output node configuration")
    parser.add_option("--dump-server", default=False, action="store_true",
                      help="Don't execute click; just output server configuration")
    parser.add_option("--verify", default=False, action="store_true")
    (opts, args) = parser.parse_args()

    if len(args) > 0:
        parser.error("too many arguments")
        
    if opts.config is None:
        parser.error("no config file specified (-c)")

    testbed = "citysense"
    file_start = 1260372827
    duration = 10
    pcap_dir = "channel-event-pcaps"
    
    # the traces will (synthetically) start running 1 minute from now
    real_start = time.time() + 60

    if opts.run == 1:
        # citysense003_ch2.pcap
        event_start = 1260373225.841107
        source = "00:18:0A:50:64:5C"
        channel = 2
    elif opts.run == 2:
        # citysense002_ch1.pcap
        event_start = 1260372883.627884
        source = "00:1E:2A:74:59:4E"
        channel = 1
    elif opts.run == 3:
        # citysense006_ch6.pcap
        event_start = 1260374579.968732
        source = "00:18:DE:0C:6F:A0"
        channel = 6
    elif opts.run == 4:
        # citysense011_ch6.pcap
        event_start = 1260374326.668627
        source = "00:22:5F:5E:E0:46"
        channel = 6
    elif opts.run == 5:
        # citysense004_ch11.pcap
        event_start = 1260376027.624068
        source = "00:22:FA:F3:AD:38"
        channel = 11
    elif opts.run == 6:
        # citysense006_ch11.pcap
        event_start = 1260375887.267025
        source = "00:16:B6:59:2F:A7"
        channel = 11
    elif opts.run == 7:
        # citysense010_ch1.pcap
        event_start = 1260372861.591294
        source = "00:19:E3:07:AE:12"
        channel = 1
    elif opts.run == 8:
        # citysense010_ch6.pcap
        event_start = 1260374388.022207
        source = "00:18:39:B8:95:D4"
        channel = 6
    elif opts.run == 9:
        # citysense006_ch11.pcap
        event_start = 1260375904.612537
        source = "00:24:2B:BB:83:05"
        channel = 11
    elif opts.run == 10:
        # citysense002_ch1.pcap
        event_start = 1260373028.703442
        source = "00:1B:2A:AC:38:00"
        channel = 1
    else:
        raise ValueError(opts.run)

    print "file start time (fixed):", file_start
    print "event start:", event_start

    adjusted_event_start = event_start - 300*(channel-1)
    print "adjusted event start:", adjusted_event_start, \
          " (%f seconds into trace)" % (adjusted_event_start - file_start)
    print "event duration:", event_duration
    print "event channel:", channel
    print "event source:", source

    args = (file_start, real_start, event_start, channel, duration, source, pcap_dir)
    
    gen_pkt_src = lambda lines, loglvls: \
                  argos.gen_fake_packet_source(lines, loglvls, *args)

    # note: use a big waitqueuelen limit to try to ensure marked packets
    # don't get dropped
    run_queries.run(opts.config, testbed, gen_pkt_src, opts,
                    ol_waitqueue_capac=10000)

if __name__ == '__main__':
    main()
