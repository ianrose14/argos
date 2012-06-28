NodeInfo(192.168.144.12 12);

db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

from_pcap::FromDump(-, MMAP false, TIMING false, END_CALL stop)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> BSSIDFilter(12:00:00:00:00:00)
    -> BSSIDFilter(12:00:00:00:00:01)
    -> BSSIDFilter(12:00:00:00:00:02)
    -> SetSniffer(SNIFFER 192.168.144.12)
    -> apc::APChannelTracker(LOGGING DEBUG)
    -> server::APChannelTracker(DB db)
    -> Discard;

apc[1] -> Script(TYPE PACKET, print "bad packet output!!", write from_pcap.active false, return 0)
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 256, DETAILED true, TIMESTAMP true)
    -> Script(TYPE PACKET, stop);
