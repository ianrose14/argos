NodeInfo(192.168.144.12 12);

db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

from_pcap::FromDump(-, MMAP false, TIMING false, STOP true)
    -> AdjustTimestamp()
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> SetSniffer(SNIFFER 192.168.144.12)
    -> prt::ProbeRequestTracker(LOGGING DEBUG)
    -> server::ProbeRequestTracker(DB db)
    -> Discard;

prt[1] -> Script(TYPE PACKET, print "bad packet output!!", write from_pcap.active false, return 0)
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 256, DETAILED true, TIMESTAMP true)
    -> Script(TYPE PACKET, stop);
