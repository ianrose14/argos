define($ETHERTYPE_IP 0x0800);
define($ETHERTYPE_ARP 0x0806);
define($ETHERTYPE_IPV6 0x86dd);
define($ETHERTYPE_VLAN 0x8100);

fd::FromDump(-, MMAP false, STOP true)
    -> RadiotapDecap()
    -> cl::WifiEtherClassifier($ETHERTYPE_IP, $ETHERTYPE_ARP, $ETHERTYPE_IPV6, $ETHERTYPE_VLAN, -);

cl[0] -> PrettyPrint("-- IP --   ", DLT IEEE802_11, MAXLENGTH 256, DETAILED false) -> Discard;
cl[1] -> PrettyPrint("-- ARP --  ", DLT IEEE802_11, MAXLENGTH 256, DETAILED false) -> Discard;
cl[2] -> PrettyPrint("-- IPv6 -- ", DLT IEEE802_11, MAXLENGTH 256, DETAILED false) -> Discard;
cl[3] -> PrettyPrint("-- VLAN -- ", DLT IEEE802_11, MAXLENGTH 256, DETAILED false) -> Discard;
cl[4] -> PrettyPrint("-- n/a --  ", DLT IEEE802_11, MAXLENGTH 256, DETAILED false) -> Discard;
