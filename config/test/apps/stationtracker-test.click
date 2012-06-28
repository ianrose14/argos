db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

fd::FromDump(-, MMAP false, TIMING false, END_CALL foo.foo)
    -> RadiotapDecap()
    -> BSSIDFilter(12:00:00:00:00:00)
    -> BSSIDFilter(12:00:00:00:00:01)
    -> BSSIDFilter(12:00:00:00:00:02)
    -> WifiStripFCS()
    -> t::Tee()
    -> raw_sta::StationTracker(NODE_ID 5555, LOGGING DEBUG);

raw_sta -> sta_server::StationTracker(SERVER true, DB db);
raw_sta[1] -> bad::Script(TYPE PACKET, print "bad packet output!!", write fd.active false, return 0)
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 256, DETAILED true, TIMESTAMP true)
    -> Script(TYPE PACKET, stop);

// not really merged, just testing the DB inserts
t[1] -> merged_sta::StationTracker(NODE_ID 7777, MERGED true, LOGGING DEBUG);
merged_sta -> sta_server;
merged_sta[1] -> bad;

foo::Script(TYPE PROXY,
            print "calling send_now",
            write raw_sta.send_now,
            write merged_sta.send_now,
            wait 1,
            stop);
