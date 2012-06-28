from_pcap::FromDump(-, STOP true)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> check::CheckWifi(VERBOSE true)
    -> Discard;

check[1] -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 140, NUMBER true,
                   DETAILED true, TIMESTAMP true)
    -> Discard;
