#!/usr/bin/env python

import sys
import dictify
import resource
import time

def main():
    s = 'foo=1  bar="chose"  x  p="aweomse  sdsd"  zal=4  foo=9'

    last = time.time()
    
    while 1:
        now = time.time()
        if now > last + 1:
            res = resource.getrusage(resource.RUSAGE_SELF)
            maxrss = res.ru_maxrss
            mbytes = maxrss*resource.getpagesize()/float(1024*1024)
            print "maxrss: %u pages (%u MB)" % (maxrss, mbytes)
            last = now
        else:
            # do some work!
            for i in range(100*1000):
                vals = dictify.dictify(s)
                if vals is None:
                    raise ValueError("dictify returned None")
         
if __name__ == '__main__':
    main()
