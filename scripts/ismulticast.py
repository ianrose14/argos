#!/usr/bin/env python

import sys

def main():
    args = sys.argv[1:]
    if len(args) == 1:
        macstr = args[0]
        if ":" in macstr:
            fields = macstr.split(":")
        else:
            fields = macstr.split("-")

        if len(fields) != 6:
            print >>sys.stderr, "malformed mac address"
            exit(1)

        highbyte = int(fields[0], 16)
        if highbyte & 0x1:
            print 1
        else:
            print 0

if __name__ == '__main__':
    main()
