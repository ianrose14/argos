db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

fd::FromDump(-, MMAP false, TIMING false, END_CALL foo.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> bss::BSSTracker()
    -> server::BSSTracker(DB db, LOGGING DEBUG) -> Discard;

bss[1] -> Script(TYPE PACKET, print "bad packet output!!", write fd.active false, return 0)
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 256, DETAILED true, TIMESTAMP true)
    -> Script(TYPE PACKET, stop);

foo::Script(TYPE PROXY,
            read bss.bss_count,
            read bss.dump_all,
            read server.bss_count,
            read server.dump_all,
            stop);
