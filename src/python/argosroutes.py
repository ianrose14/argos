#!/usr/local/bin/python

#
# IMPORTS
#

# system modules
import datetime
from optparse import OptionParser
import socket
import sys
import time

# third-party modules
import psycopg2


#
# CONSTANTS
#
BBN_WIRED_NODES = ["citysense262", "citysense274"]
CITYSENSE_WIRED_NODES = ["citysense001", "citysense002"]


#
# GLOBAL VARIABLES
#
# map from hostnames and IP addresses to hostnames
rev_dns = {}

# map from testbed names to lists of hostnames
testbeds = {}

# map from (src, dst) pairs to (gateway, usage-count) pairs
routes = {}


#
# METHODS
#

def get_outdoor_testbeds():
    return ["bbn", "harvard", "mystic", "rowland"]

# returns (hostname, is-wired) tuple
def get_next_hop(src, dst):
    if len(routes) == 0:
        raise StandardError("routes not initialized")
    
    src = to_hostname(src)
    dst = to_hostname(dst)

    # all citymd nodes are wired
    if src.startswith("citymd") and dst.startswith("citymd"):
        return (dst, True)
    
    if is_wired(src) and dst == "citysense":
        return (dst, True)

    if src == "citysense" and is_wired(dst):
        return (dst, True)

    if (src in BBN_WIRED_NODES) and (dst in BBN_WIRED_NODES):
        return (dst, True)

    if (src in CITYSENSE_WIRED_NODES) and (dst in CITYSENSE_WIRED_NODES):
        return (dst, True)

    key = (src, dst)
    if key in routes:
        (gateway, count) = routes[key]
        return (gateway, False)  # wireless link

    raise ValueError("no known route from %s to %s" % (src, dst))

def get_nodes(testbed):
    if len(testbed) == 0:
        raise StandardError("initialize() not called")
        
    return testbeds[testbed]

def initialize(timestamp=None, force=False, init_routes=True):
    if not force and (len(testbeds) > 0):
        return

    # Fill in testbeds and rev_dns maps:
    # Although we could easily pull these from the citymd database, we
    # intentionally hard-code them so that we can be sure what we are going to
    # get (e.g. if people add nodes or otherwise change the database, I may not
    # want those changes to be reflected in the nodes that I deal with).
    # Also, we include some "fake" testbeds that reuse nodes from other testbeds.

    # indoor CityMD testbed
    testbeds["citymd"] = ["citymd%03d" % i for i in range(1,15)]

    # Harvard outdoor nodes
    ids = [1, 2, 3, 4, 6, 7, 10, 11, 12]
    testbeds["harvard"] = ["citysense%03d" % i for i in ids]

    # BBN outdoor nodes
    ids = [259, 261, 262, 263, 264, 266, 268, 270, 271, 273, 274, 275, 276]
    testbeds["bbn"] = ["citysense%03d" % i for i in ids]
    
    # Rowland outdoor nodes
    testbeds["rowland"] = ["citysense%03d" % i for i in [513, 514]]
    
    # Mystic Activity Center, Somerville outdoor nodes
    testbeds["mystic"] = ["citysense%03d" % i for i in [769, 770]]

    for nodelist in testbeds.itervalues():
        for node in nodelist:
            mgmt_ip = socket.gethostbyname("%s-mgmt" % node)
            rev_dns[node] = node
            rev_dns[mgmt_ip] = node
            if is_wired(node):
                wired_ip = socket.gethostbyname("%s-wired" % node)
                rev_dns[wired_ip] = node

    # lastly, fill in the citysense server's various IP addresses and aliases
    rev_dns["citysense"] = "citysense"
    rev_dns["citysense.eecs.harvard.edu"] = "citysense"  # normalization
    rev_dns["citysense.net"] = "citysense"  # normalization
    rev_dns["www.citysense.net"] = "citysense"  # normalization
    rev_dns["192.168.10.254"] = "citysense"
    rev_dns["192.168.11.254"] = "citysense"
    rev_dns["192.168.14.254"] = "citysense"
    rev_dns["192.168.128.0/20"] = "citysense"
    rev_dns["192.168.128.254"] = "citysense"

    # this is an IP for citysense-bbn but we can pretend that's the same machine
    # as citysense.net
    rev_dns["192.168.1.10"] = "citysense"

    # citysense005 used to be part of the Harvard network
    rev_dns["192.168.144.5"] = "citysense005"

    # if requested, also load routes (this is optional because it requires a
    # database query and thus might take some time which is annoying if you don't
    # even care about the routes)
    if init_routes:
        # if timestamp is quite recent, we might miss routes simply because
        # netmeas hasn't run recently enough (or some node(s) were offline during
        # the last netmeas), so expand the select range so we can be pretty sure
        # to get all of the routes we need
        lim = datetime.datetime.now() - datetime.timedelta(hours=2)
        if timestamp is None or timestamp > lim:
            timestamp = lim
    
        databases = ["citysense_netmeas", "bbn_netmeas"]
        for db in databases:
            dbconn = psycopg2.connect("user=ianrose password=ianrose dbname=%s" % db)
            cur = dbconn.cursor()

            sql = "select from_host, to_host, gateway, count(*) from olsr" + \
                  " where timestamp >= %s group by from_host, to_host, gateway"
            args = [timestamp]
        
            cur.execute(sql, args)

            while 1:
                row = cur.fetchone()
                if row is None:
                    break

                (from_host, to_host, gateway, count) = row
                
                try:
                    from_host = to_hostname(from_host)
                    to_host = to_hostname(to_host)
                except ValueError:
                    # this is some host we don't care about - skip it
                    continue

                # ignore citysense005
                if from_host == "citysense005" or to_host == "citysense005":
                    continue

                try:
                    gateway = to_hostname(gateway)
                except ValueError:
                    # in this case we DO care!
                    raise ValueError("to_hostname(%s) failed!  to_host=%s from_host=%s gw=%s" % \
                                     (gateway, to_host, from_host, gateway))
                
                key = (from_host, to_host)
                if key in routes:
                    (cur_gw, cur_count) = routes[key]
                    if count > cur_count:
                        routes[key] = (gateway, count)
                else:
                    routes[key] = (gateway, count)

def is_wired(host):
    return (host in BBN_WIRED_NODES) or (host in CITYSENSE_WIRED_NODES)

def to_hostname(arg):
    if len(rev_dns) == 0:
        raise StandardError("initialize() not called")
    
    v = rev_dns.get(arg, None)
    if v is None:
        raise ValueError("unknown host/IP: %s" % str(arg))
    else:
        return v

def walk_route(src, dst):
    if len(routes) == 0:
        raise StandardError("routes not initialized")
    
    src = to_hostname(src)
    dst = to_hostname(dst)
    
    links = []
    node = src
    iters = 0
    all_wired = True

    while node != dst:
        iters += 1
        if iters > 20:
            raise ValueError("too many hops in walk_route() from %s -> %s", src, dst)
        
        (hop, is_wired) = get_next_hop(node, dst)

        if node == hop:
            raise ValueError(node)

        # its not correct to simply append wireless links to links[] but not wired
        # links, because a path like wireless -> wired -> wireless is impossible
        # with our current architecture; once you start wireless you must stay
        # wireless for that whole route
        if not is_wired:
            all_wired = False

        # special case
        if hop == "citysense":
            if hop == dst:
                break
            else:
                raise ValueError("citysense.net is an intermediate hop?!")

        # keep link endpoints in sorted order so that a->b == b->a
        if hop < node:
            links.append((hop,node))
        else:
            links.append((node,hop))

        node = hop

    if all_wired:
        return []
    else:
        return links

#
# Main
#
def main():
    parser = OptionParser(usage="%prog [options] [NODE] ...")
    parser.add_option("--hostnames", default=False, action="store_true",
                      help="Print all hostname/IP mappings")
    parser.add_option("--nodes", default=False, action="store_true",
                      help="Print all node hostnames and testbeds")
    parser.add_option("--routes", default=False, action="store_true",
                      help="Print routing table")
    parser.add_option("-t", "--testbed", default=None,
                      help="Print all nodes in the specified testbed")
    parser.add_option("--timestamp", default=None,
                      help="Load routes from a specific date (default: today)")
    (opts, args) = parser.parse_args()

    if opts.timestamp is None:
        now = datetime.datetime.now()
        initialize(now - datetime.timedelta(days=1))
    else:
        dt = datetime.datetime.strptime(opts.timestamp, "%Y-%m-%d")
        initialize(dt)

    if opts.hostnames:
        for arg in sorted(rev_dns.keys()):
            print "%s -> %s" % (arg, rev_dns[arg])
        return

    if opts.nodes:
        for testbed in sorted(testbeds.keys()):
            print "%s: %s" % (testbed, str(testbeds[testbed]))
        return

    if opts.testbed is not None:
        nodes = get_nodes(opts.testbed)
        if len(nodes) == 0:
            print "no nodes in testbed \"%s\"" % opts.testbed
        else:
            for node in nodes:
                print node
        return

    if len(args) == 0:
        hosts = set()
        for key, val in routes.items():
            (src, dst) = key
            hosts.add(src)
            hosts.add(dst)

        hosts = sorted(hosts)

        for src in hosts:
            for dst in hosts:
                key = (src, dst)
                if key in routes:
                    (gateway, count) = routes[key]
                    if gateway == dst:
                        print "%s -> %s (direct)" % (src, dst)
                    else:
                        print "%s -> %s uses gateway %s" % (src, dst, gateway)
    elif len(args) == 2:
        links = walk_route(args[0], args[1])
        if len(links) == 0:
            print "(no links)"
        else:
            for link in links:
                print link
    else:
        print "usage: argosroutes.py [options] [src dst]"

if __name__ == '__main__':
    main()
