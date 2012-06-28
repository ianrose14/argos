#!/usr/bin/env python

#
# IMPORTS
#

# system modules
from optparse import OptionParser
import re
import signal
import subprocess
import sys

# local modules
sys.path.append("lib/python")
import ansi
import argoslog


#
# METHODS
#
def format_line(entry, minlvl, highlight=False):
    if highlight:
        # level doesn't matter
        return ansi.format(str(entry), ['bold', 'yellow'])
    
    if entry.loglevel < minlvl:
        return None

    if entry.loglevel == argoslog.LOG_DEBUG:
        return ansi.format(str(entry), ['green'])
    elif entry.loglevel == argoslog.LOG_DATA:
        return str(entry)
    elif entry.loglevel == argoslog.LOG_INFO:
        return str(entry)
    elif entry.loglevel == argoslog.LOG_WARN:
        return ansi.format(str(entry), ['bold', 'cyan'])
    elif entry.loglevel == argoslog.LOG_ERR:
        return ansi.format(str(entry), ['bold', 'red'])
    elif entry.loglevel == argoslog.LOG_CRIT:
        return ansi.format(str(entry), ['bold', 'red'])
    else:
        return ansi.format("[unrecognized loglevel] ", ['bold', 'red']), str(entry)

#
# MAIN
#
def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    
    parser = OptionParser(usage="%prog [options]")
    parser.add_option("-l", "--level", type="choice", default="DEBUG",
                      choices=["DEBUG", "DATA", "INFO", "WARN", "ERR", "CRIT"])
    parser.add_option("--grep", action="store", default=None,
                      help="specify a regexp; matching lines are highlighted")
    parser.add_option("--pager", action="store_true", default=False)
    parser.add_option("-s", "--sources", default="",
                      help="comma delimited list of sources to highlight")
    parser.add_option("--window", type="int", action="store", default=0)
    (opts, args) = parser.parse_args()

    minlvl = argoslog.parse_loglevel(opts.level)
    sources = []

    for elt in opts.sources.split(","):
        sources.append(elt.strip())

    view_rows = 0

    streams = []
    if len(args) > 0:
        for arg in args:
            fi = open(arg, "r")
            streams.append(fi)
    else:
        streams.append(sys.stdin)

    entries = []

    if opts.pager:
        proc = subprocess.Popen(["less", "-R"], stdin=subprocess.PIPE)
        out = proc.stdin
    else:
        proc = None
        out = sys.stdout

    pat = None
    if opts.grep is not None:
        pat = re.compile(opts.grep)

    # malformed lines are printed like WARN entries unless they match the GREP
    # option
    def bad_line_handler(line):
        if (pat is not None) and (pat.search(line) is not None):
            print >>out, ansi.format(line, ['bold', 'yellow'])
        else:
            print >>out, ansi.format(line, ['bold', 'cyan'])
        
    for stream in streams:
        for entry in argoslog.parse(stream, window=opts.window, errh=bad_line_handler):
            if entry.source in sources:
                txt = format_line(entry, minlvl, True)
            elif (pat is not None) and (pat.search(str(entry)) is not None):
                txt = format_line(entry, minlvl, True)
            else:
                txt = format_line(entry, minlvl)
            if txt is not None:
                print >>out, txt

    out.close()
    if proc is not None:
        proc.wait()

if __name__ == '__main__':
    main()
