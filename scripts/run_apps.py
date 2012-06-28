#!/usr/bin/env python

import os
import sys

def main():
    args = sys.argv[1:]
    if len(args) != 1:
        print >>sys.stderr, "usage: run_apps.py CLICK-EXE"
        sys.exit(1)

    os.execlp("python", "python", "./scripts/run_queries.py",
              "-c", "config/run-apps.argos", "-d", "-o", "data/apps/",
              "--db", "argos", "--db-user", "argos", args[0])

if __name__ == '__main__':
    main()
