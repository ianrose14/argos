from_pcap::FromDump(-, MMAP false, END_CALL foo.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> assoc::AssocTracker(VERBOSE true)
    -> Discard;

foo::Script(TYPE PROXY,
            read assoc.client_count,
            read assoc.infra_ap_count,
            read assoc.ibss_ap_count,
            read assoc.station_count,
            read assoc.dump_all,
            stop);
