define($PORTS 80 8000 67-68 1900 5000-10000 1-65535)

db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

fd::FromDump(-, TIMING false, MMAP false, END_CALL foo.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> t::Tee()
    -> raw_tracker::TrafficCounter(DLT IEEE802_11, NODE_ID 5555, TCP_PORTS $PORTS, UDP_PORTS $PORTS, LOGGING DEBUG)
    -> Discard;

raw_tracker[1] -> server::TrafficCounter(SERVER true, DB db, LOGGING DEBUG);

// not really merged, just testing the DB inserts
t[1] -> merged_tracker::TrafficCounter(DLT IEEE802_11, NODE_ID 7777, MERGED true, TCP_PORTS $PORTS, UDP_PORTS $PORTS, LOGGING DEBUG) -> Discard;
merged_tracker[1] -> server;

foo::Script(TYPE PROXY,
            print "calling send_now",
            write raw_tracker.send_now,
            write merged_tracker.send_now,
            wait 1,
            stop);
