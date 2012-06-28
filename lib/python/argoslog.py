#!/usr/bin/env python

#
# IMPORTS
#

# system modules
import datetime
import heapq
from optparse import OptionParser
import re
import shlex
import sys
import time
import types


#
# CONSTANTS
#
LOG_DEBUG=0
LOG_DATA=1
LOG_INFO=2
LOG_WARN=3
LOG_ERR=4
LOG_CRIT=5

LOG_LEVEL_DESCS = ["DEBUG", "DATA", "INFO", "WARN", "ERR", "CRIT"]


#
# CLASSES
#
class LogEntry:
    def __init__(self, dt, source, loglevel, data, linenum=-1):
        self.datetime = dt
        self.source = source
        self.logleveldesc = loglevel
        self.loglevel = parse_loglevel(loglevel)
        self.data = data
        self.linenum = linenum
        
        self.timestamp = time.mktime(dt.timetuple()) + \
                         float(dt.microsecond)/1000000

    def __cmp__(self, other):
        return cmp(self.timestamp, other.timestamp)

    def __str__(self):
        datedesc = self.datetime.ctime()
        
        # trunc off 'Thu ' at front and '1986' at end
        datedesc = datedesc[4:-5]
        msec = self.datetime.microsecond / 1000
        return "%s.%03d %-15s %-5s %s" % (datedesc, msec, self.source, \
                                          self.logleveldesc, self.data)

class ParseError:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)
    

#
# METHODS
#
def parse(stream, window=60, errh=None):
    # date format in log does not include the year so we guess based on the month
    now = time.localtime()

    # due to network logging, timestamps in log can be out of order sometimes;
    # use windowing to try to ensure we output only in sorted order
    entries = []
    max_ts = 0
    linenum = 0

    # not 100% clear why, but 'for line in stream' can have some buffering issues
    # when reading from a piped stdin, but the following seems to be ok
    while 1:
        line = stream.readline()
        if line == "":
            break
        
        linenum += 1

        if window > 0:
            while (len(entries) > 0) and (max_ts - entries[0].timestamp) >= window:
                yield heapq.heappop(entries)

        if len(entries) == 0:
            max_ts = 0

        entry = parse_line(line, now)
        if entry is None:
            # parsing failed
            if errh is not None:
                errh(line.strip())
        else:
            entry.linenum = linenum
            if window > 0:
                heapq.heappush(entries, entry)
                max_ts = max(max_ts, entry.timestamp)
            else:
                yield entry

    # done reading from file - now just empty whatever is in the heap
    while len(entries) > 0:
        yield heapq.heappop(entries)

def parse_line(line, tm=None):
    if tm is None:
        tm = time.localtime()
        
    # line format:
    # MON DAY TIME SOURCE     LEVEL   MESSAGE
    # ex: Oct 22 08:54:36.075 script          INFO  SERVER-STATS count=40 bytes=8041
    fields = line.split(None, 5)
    if len(fields) != 6:
        # whatever - some malformed line
        return None
    
    (timestr, _, msec) = fields[2].partition(".")

    try:
        dt = datetime.datetime.strptime(fields[0], "%b")
        if dt.month > tm.tm_mon:
            year = tm.tm_year -1  # assume last year
        else:
            year = tm.tm_year # assume this year
            
        arg = "%s %s %s %d" % (fields[0], fields[1], timestr, year)
        dt = datetime.datetime.strptime(arg, "%b %d %H:%M:%S %Y")
    except ValueError:
        # assume this is also a malformed line
        return None
    
    assert(dt.microsecond == 0)
    dt = dt + datetime.timedelta(milliseconds=int(msec))
    return LogEntry(dt, fields[3], fields[4], fields[5].strip())

def parse_loglevel(desc):
    for i in range(len(LOG_LEVEL_DESCS)):
        if desc == LOG_LEVEL_DESCS[i]:
            return i
    return -1
    
def unparse_loglevel(level):
    if (level >= 0) and (level < len(LOG_LEVEL_DESCS)):
        return LOG_LEVEL_DESCS[level]
    else:
        return "(invalid)"

if __name__ == '__main__':
    parser = OptionParser(usage="%prog [options]")
    parser.add_option("--window", type="int", action="store", default=0)
    (opts, args) = parser.parse_args()

    for arg in args:
        fi = open(arg, "r")
        print "parsing %s" % arg
        for elt in parse(fi, window=opts.window):
            pass

