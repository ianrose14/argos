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
import argoslog


#
# MAIN
#
def main():
    parser = OptionParser(usage="%prog FILE (or DIR)")
    (opts, args) = parser.parse_args()

    logs = []
       
    if len(args) == 0:
        logs.append("-")
    else:
        for arg in args:
            if os.path.isdir(arg):
                for (dirpath, dirnames, filenames) in os.walk(arg):
                    for filename in filenames:
                        # assume that only files ending with '.log' are meant to be
                        # processed
                        if filename.endswith(".log"):
                            filepath = os.path.join(dirpath, filename)
                            logs.append(filepath)
            else:
                # arg is a logfile
                logs.append(arg)

    bad_lines = []

    def print_it(line):
        print line

    for log in logs:
        if log is "-":
            fi = sys.stdin
        else:
            fi = open(log, "r")
            
        for entry in argoslog.parse(fi, errh=print_it):
            if entry.source != "wifi_ol":
                print str(entry)
                continue
            
            (head, _, tail) = entry.data.partition(" ")
            if tail == "":
                print str(entry)
                continue
                
            if head not in ["SEND-DETAILS", "NET-USAGE"]:
                print str(entry)
                continue
                
            parts = tail.split("|")
            for part in parts:
                newdata = head + " " + part
                newentry = argoslog.LogEntry(entry.datetime, entry.source,
                                             entry.logleveldesc, newdata, entry.linenum)
                print str(newentry)

        if fi != sys.stdin:
            fi.close()

if __name__ == '__main__':
    main()
