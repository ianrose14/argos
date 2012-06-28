from_pcap::FromDump(-, TIMING true, MMAP false, END_CALL foo.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> wf::WifiFingerprint(SERVER true, LOGGING DATA, INTERVAL 5);

foo::Script(TYPE PROXY, print "file complete!");

Script(wait 10,
       print "----------------------------------",
       read wf.count,
       read wf.rate,
       read wf.client_count,
       read wf.client_rate,
       read wf.avg_len,
       loop);
