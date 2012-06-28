#!/usr/bin/env python

#
# Imports
#

# stdlib imports
import httplib
from optparse import OptionParser
import os
import pickle
import re
import sys
import time
import urllib


__all__ = ["WigleCache", "WigleError", "login", "lookup"]


#
# CONSTANTS
#

th_pattern=re.compile('<th class="searchhead">(.*?)</th>', re.MULTILINE + re.DOTALL)
row_pattern=re.compile('<tr class="search">(.+?)</tr>', re.MULTILINE + re.DOTALL)
td_pattern=re.compile('<td>(.*?)</td>', re.MULTILINE + re.DOTALL)

# also available: 'arose/arose'
WIGLE_DEF_LOGIN="ianrose"
WIGLE_DEF_PASS="ianrose"


#
# CLASSES
#
class WigleCache:
    def __init__(self):
        # the keys to this dict are 2-tuples of (field, value)
        self.vals = {}
        self.modified = False

    def __contains__(self, item):
        return (item in self.vals)

    def __iter__(self):
        return self.vals.iteritems()
        
    def get(self, field, value):
        key = (field, value)
        return self.vals.get(key, None)

    def load(self, filename):
        fi = open(filename, "r")
        self.vals = pickle.load(fi)
        fi.close()

    def put(self, field, value, results, overwrite=False):
        key = (field, value)
        if overwrite and (key in self.vals):
            raise StandardError("Cannot overwrite existing key %s" % str(key))
        self.vals[key] = results
        self.modfied = True

    def save(self, filename, force=False):
        if not self.modified:
            return
        fi = open(filename, "w")
        pickle.dump(self.vals, fi, pickle.HIGHEST_PROTOCOL)
        fi.close()

class WigleError(StandardError):
    def __init__(self, value, query=None):
        self.value = value

    def __str__(self):
        return str(self.value)


#
# METHODS
#

def filter_ssids(results, ssid):
    filtered = []
    for result in results:
        # wigle allows partial matching on some fields (like SSID) so filter
        # those rows out
        if "ssid" in result and result["ssid"] != ssid:
            continue
        # else, result must be ok
        filtered.append(result)

    return filtered

def filter_bad_latlongs(results):
    near_zero = lambda x: (x < 0.000001 and x > -0.000001)

    # first check if ANY of the results are of type 'infrastructure'
    has_infra = False
    for result in results:
        if result.get("type", "").lower().startswith("infra"):
            has_infra = True
            break

    filtered = []
    for result in results:
        # wigle sometimes has (0,0) for the coordinates which we can safely
        # assume is wrong
        if "trilat" in result and "trilong" in result and \
                near_zero(float(result["trilat"])) and \
                near_zero(float(result["trilong"])):
            continue

        if has_infra:
            if not result.get("type", "").lower().startswith("infra"):
                continue
            # else, result is ok
        else:
            # if none of the results are of type "infrastructure", then we save
            # all results that are not explicitly ad-hoc networks or probe
            # requests/responses
            if "probe" in result.get("type", "").lower():
                continue
            if "hoc" in result.get("type", "").lower():
                continue
            # else, result is ok

        filtered.append(result)

    return filtered

# returns a tuple of (connection, cookie)
def login(login=WIGLE_DEF_LOGIN, password=WIGLE_DEF_PASS):
    # note - HTTPS seems to hang
    wwwconn = httplib.HTTPConnection("wigle.net", strict=True)
    params = urllib.urlencode({"credential_0": login,
                               "credential_1": password,
                               "destination": "/gps/gps/main/",
                               "login": "1"})
    headers = {"Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    wwwconn.request("POST", "/gps/gps/main/login", params, headers)
    response = wwwconn.getresponse()
    if response.status != 200:
        raise WigleError("login failure (%s %s)" % (response.status, response.reason))

    for (header, value) in response.getheaders():
        if header == "set-cookie":
            return (wwwconn, value)

    # else, fail
    wwwconn.close()
    raise WigleError("login error: no cookie in response!")

# returns a list of dicts, where each dict is indexed by column name and contains
# the values from a single returned row
def lookup(field, value, wwwconn, cookie, cache=None, cache_only=False):
    global th_pattern, row_pattern, td_pattern

    # try the cache first
    got_cache = False
    if cache is not None:
        v = cache.get(field, value)
        if v is not None:
            got_cache = True
            results = v

    if not got_cache:
        if cache_only:
            return []
        else:
            results = query(field, value, wwwconn, cookie)
            if cache is not None:
                cache.put(field, value, results)

    return results

def query(field, value, wwwconn, cookie):
    params = urllib.urlencode({field: value, "Query": "Query"})
    headers = {"Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain",
               "Cookie": cookie}
    wwwconn.request("POST", "/gps/gps/main/confirmquery/", params, headers)
    response = wwwconn.getresponse()
    if response.status != 200:
        raise WigleError("query failure (%s %s)" % (response.status, response.reason),
                         (field, value))

    html = response.read()

    if html.find("too many queries") != -1:
        raise WigleError("too many queries error", (field, value))

    columns = []
    for match in th_pattern.finditer(html):
        columns.append(match.group(1))

    if len(columns) == 0:
        # I have (rarely) seen the word 'error' as part of normal search results,
        # so do not search for unknown errors unless the column headers cannot
        # be found
        i = html.find("Error")
        if i == -1:
            i = html.find("error")

        if i != -1:
            raise WigleError("unknown wigle.net error... %s" % html[i:], (field, value))
        else:
            raise WigleError("parsing failure: no header row found", (field, value))

    results = []
    for r_match in row_pattern.finditer(html):
        d = {}
        i = 0
        for match in td_pattern.finditer(r_match.group(1)):
            val = match.group(1).strip()
            if val in ["", "&nbsp;", "<no ssid>", "?"]:
                pass
            else:
                d[columns[i]] = val
            i += 1
        results.append(d)

    return results

def main():
    parser = OptionParser(usage="%prog ARG [...]")
    parser.add_option("--cache", default="data/wigle.pickle")
    parser.add_option("-a", "--all", action="store_true", default=False)
    parser.add_option("-l", "--long", action="store_true", default=False)
    parser.add_option("--dump", action="store_true", default=False,
                      help="do not do a lookup; print contents of cache file instead")
    parser.add_option("--dump-keys", action="store_true", default=False,
                      help="do not do a lookup; print keys of cache file instead")
    parser.add_option("--ssid", action="store_true", default=False,
                      help="Specify that ARGS are SSIDs, not BSSIDs")
    parser.add_option("--cache-only", action="store_true", default=False,
                      help="If results not available in cache, do not perform lookup")
    parser.add_option("--via", action="store", metavar="BSSID")
    (opts, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("no arguments!")

    if opts.cache == "":
        opts.cache = None

    if opts.cache is None:
        cache = None
    else:
        cache = WigleCache()
        if os.path.exists(opts.cache):
            cache.load(opts.cache)

    if opts.dump:
        if opts.cache is None:
            print >>sys.stderr, "no cache file specified"
            sys.exit(1)
        else:
            for key, value in cache:
                # repr() will escape any unprintable ssids
                print repr(key), value
            return
    elif opts.dump_keys:
        if opts.cache is None:
            print >>sys.stderr, "no cache file specified"
            sys.exit(1)
        else:
            for key, value in cache:
                # repr() will escape any unprintable ssids
                print repr(key)
            return

    (conn, cookie) = login()

    for arg in args:
        if opts.ssid:
            results = lookup("ssid", arg, conn, cookie, cache=cache, cache_only=opts.cache_only)
            # always filter non-matching ssids
            results = filter_ssids(results, arg)

        elif opts.via is not None:
            results = lookup("ssid", opts.via, conn, cookie, cache=cache, cache_only=opts.cache_only)
            # always filter non-matching ssids
            results = filter_ssids(results, opts.via)
            hits = []
            for result in results:
                if "netid" in result and result["netid"] == arg:
                    hits.append(result)
            results = hits
        else:
            # search by BSSID, which wigle calls "netid"
            results = lookup("netid", arg.upper(), conn, cookie, cache=cache)

        points = []
        if opts.all:
            print arg
            print
            for result in results:
                for key, value in result.iteritems():
                    if key not in "map it":
                        print "%s: %s" % (key, value)
                if "trilat" in result and "trilong" in result:
                    lat = result["trilat"]
                    lng = result["trilong"]
                    points.append((float(lat), float(lng)))
                    print "http://maps.google.com/?q=%s,%s" % (lat, lng)
                print
            print "-"*40
        else:
            # for normal and long views, filter out bad lat/longs
            results = filter_bad_latlongs(results)

            if opts.long:
                print arg
            
            for result in results:
                if "trilat" in result and "trilong" in result:
                    lat = result["trilat"]
                    lng = result["trilong"]
                    points.append((float(lat), float(lng)))
                    if opts.long:
                        print "http://maps.google.com/?q=%s,%s" % (lat, lng)

        if len(points) > 0:
            parts = ["http://www.citysense.net/ianrose/topos/plotlatlong.cgi?"]
            for (lat, lng) in points[:100]:
                parts.append("c=%.8f,%.8f&" % (lat, lng))

            if len(points) > 100:
                print "%s  (truncated to 100 from %d points)" % ("".join(parts), len(points))
            else:
                print "".join(parts)
                    
    conn.close()

    if cache is not None:
        cache.save(opts.cache)

if __name__ == '__main__':
    main()
