fd::FromDump(-, STOP true)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> SetSniffer(SNIFFER 192.168.144.5)  // arbitrary IP
    -> ArgosRadiotapEncap()
    -> ToDump("argosradiotapencap-test.pcap", USE_ENCAP_FROM fd);
