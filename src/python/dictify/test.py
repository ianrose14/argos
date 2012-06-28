#!/usr/bin/env python

import sys
from dictify import dictify, ParseError
from getifaddrs import getifaddrs

def main():
    li = [("a=1", {"a": "1"}),
          ("a=\"1\"", {"a": "1"}),
          ("a='1'", {"a": "1"}),
          ("a=1  ", {"a": "1"}),
          ("a=\"1\"  ", {"a": "1"}),
          ("a='1'  ", {"a": "1"}),
          ("a=  1", {"a": "1"}),
          ("a=  \"1\"", {"a": "1"}),
          ("a=  '1'", {"a": "1"}),
          ("a  =  1", {"a": "1"}),
          ("a  =  \"1\"", {"a": "1"}),
          ("a  =  '1'", {"a": "1"}),
          ("a='1 '", {"a": "1 "}),
          ("a=' 1'", {"a": " 1"}),
          ("a= ' 1 '", {"a": " 1 "}),
          ("a =' 1 '", {"a": " 1 "}),
          ("a = ' 1 ' ", {"a": " 1 "}),
          ("a='1\"'", {"a": "1\""}),
          ("a=\"1'\"", {"a": "1'"}),
          ("a=\"1'2'3\"", {"a": "1'2'3"}),
          ("a='\"123\"'", {"a": "\"123\""}),
          ("a", {"a": None}),
          ("a   ", {"a": None}),
          ("   a", {"a": None}),
          ("   a   ", {"a": None}),
          ("a=", None),
          ("  a=", None),
          ("  a=  ", None),
          ("a=\"", None),
          ("a=\"b", None),
          ("a='b", None),
          ("a=\"  ", None),
          ("a=\"b  ", None),
          ("a='b  ", None),
          ("a=\"  ", None),
          ("a=\"b'bb", None),
          ("a='b\"bb", None),
          ("a=1 b=2", {"a": "1", "b": "2"}),
          ("a=1 b= 2", {"a": "1", "b": "2"}),
          ("a=1 b =2", {"a": "1", "b": "2"}),
          ("a=1 b = 2", {"a": "1", "b": "2"}),
          ("a=1 b=2 ", {"a": "1", "b": "2"}),
          ("a=1 b = 2 ", {"a": "1", "b": "2"}),
          (" a = 1 b = 2 ", {"a": "1", "b": "2"}),
          ("a=1 b='2'", {"a": "1", "b": "2"}),
          ("a=1 b=\"2\"", {"a": "1", "b": "2"}),
          ("a=1 b=\"2\"   ", {"a": "1", "b": "2"}),
          ("a=1 b = \"2\" ", {"a": "1", "b": "2"}),
          ("a=1 b", {"a": "1", "b": None}),
          ("a=1 b ", {"a": "1", "b": None}),
          ("a=1   b ", {"a": "1", "b": None}),
          ("a=1 b=2", {"a": "1", "b": "2"}),
          ("a=1 b=2  ", {"a": "1", "b": "2"}),
          ("a=1 b =  2", {"a": "1", "b": "2"}),
          ("a=1 b='2'", {"a": "1", "b": "2"}),
          ("a=1 b=  \"2\"  ", {"a": "1", "b": "2"}),
          ("a=1 b=", None),
          ("a=1 b='2", None),
          ("a=1 b=\"2", None),
          ("a=1 b=  '2", None),
          ("a=1 b='2  ", None),
          ("a=1 b=  '2  ", None),
          ("a=1 b=  '2  ' ", {"a": "1", "b": "2  "}),
          ("a=1 b=2 c=3", {"a": "1", "b": "2", "c": "3"}),
          ("a=1 b=2 c=3 ", {"a": "1", "b": "2", "c": "3"}),
          ("a=1 b=2 c='3'", {"a": "1", "b": "2", "c": "3"}),
          ("x a=1 b=2 c=3", {"x": None, "a": "1", "b": "2", "c": "3"}),
          ("a=1 x b=2 c=3", {"x": None, "a": "1", "b": "2", "c": "3"}),
          ("a= 1 x b=2 c=3", {"x": None, "a": "1", "b": "2", "c": "3"}),
          ("a= 1 b=2 c=3 x", {"x": None, "a": "1", "b": "2", "c": "3"}),
          ("a= 1 b=2 c=3 x x x", {"x": None, "a": "1", "b": "2", "c": "3"}),
          ("a= 1 x b=2 c=3 x b=4 x c=5 x x", {"x": None, "a": "1", "b": "4", "c": "5"})
          ]

    for (s, expected) in li:
        try:
            rv = dictify(s)
        except ParseError, e:
            if expected is not None:
                print "test failed!  erroneous ParseError (%s)" % str(e)
                print "arg: [%s]" % s
                sys.exit(1)
        except Exception, e:
            print "unexpected exception: %s" % repr(e)
            print "arg: [%s]" % s
            print
            raise
        else:
            if expected is None:
                # exception was supposed to be raised!
                print "test failed!  expected ParseError"
                print "arg: [%s]" % s
                sys.exit(1)
            if rv != expected:
                print "test failed!  wrong result"
                print "arg: [%s]" % s
                print "expected: %s" % str(expected)
                print "result:   %s" % str(rv)
                sys.exit(1)

    print "all tests passed!"
    sys.exit(0)

if __name__ == '__main__':
    main()
