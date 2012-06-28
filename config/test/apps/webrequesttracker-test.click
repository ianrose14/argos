NodeInfo(192.168.144.12 12);

db::PostgreSQL(DATABASE argos_test, USER ianrose, PASSWORD ianrose);

wrt::WebRequestTracker(DLT EN10MB, LOGGING DEBUG);

from_pcap::FromDump(-, MMAP false, TIMING false, END_CALL foo.foo)
    -> AdjustTimestamp()
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> SetSniffer(SNIFFER 192.168.144.12)
    -> WifiDecap(STRICT true, ETHER true)
    -> cl::Classifier(12/0800)  // 0x0800 == ETHERTYPE_IP
    -> Strip(14)                // strip Ethernet header
    -> cih::CheckIPHeader()
    -> ipc::IPClassifier(dst tcp port 80, src tcp port 80);

ipc[0] -> [0]wrt;  // http requests go to WebRequestTracker input 0
ipc[1] -> [1]wrt;  // http responses go to WebRequestTracker input 1

wrt -> server::WebRequestTracker(SERVER true, DB db);
wrt[1] -> Script(TYPE PACKET, print "bad packet output!!", write from_pcap.active false, return 0)
    -> PrettyPrint(DLT EN10MB, MAXLENGTH 256, DETAILED true, TIMESTAMP true)
    -> Script(TYPE PACKET, stop);

foo::Script(TYPE PROXY,
            print "calling wrt.timeout_all",
            write wrt.timeout_all,
            wait 1,
            stop);
