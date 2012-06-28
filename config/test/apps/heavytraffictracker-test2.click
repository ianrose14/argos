from_pcap::FromDump(-, MMAP false, TIMING false, END_CALL s.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> traf::HeavyTrafficTracker(1)
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 140, NUMBER true,
                   DETAILED true, TIMESTAMP true)
    -> Discard;

s::Script(TYPE PROXY,
          print "dst: " $(traf.dst_summary),
          print,
          print "src: " $(traf.src_summary),
          print,
          print "rx: " $(traf.rx_summary),
          print,
          print "tx: " $(traf.tx_summary),
          print,
          print "bssid: " $(traf.bssid_summary),
    write traf.reset,
    stop);
