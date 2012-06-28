NodeInfo(192.168.144.12 12);

db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

from_pcap::FromDump(-, MMAP false, TIMING false, STOP true)
    -> AdjustTimestamp()
    -> RadiotapDecap()
//    -> BSSIDFilter(12:00:00:00:00:00)
//    -> BSSIDFilter(12:00:00:00:00:01)
//    -> BSSIDFilter(12:00:00:00:00:02)
    -> WifiStripFCS()
    -> SetSniffer(SNIFFER 192.168.144.12)
    -> assoc::AssocTracker(LOGGING DEBUG)
    -> server::AssocTracker(DB db)
    -> Discard;

assoc[1] -> Script(TYPE PACKET, print "bad packet output!!", write from_pcap.active false, return 0)
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 256, DETAILED true, TIMESTAMP true)
    -> Script(TYPE PACKET, stop);
