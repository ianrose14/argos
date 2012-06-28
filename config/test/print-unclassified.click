fd::FromDump(-)
    -> SetSniffer(SNIFFER 192.168.144.1)  // value shouldn't matter
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> pre_capt_cnt::Counter()
    -> filter_a::BSSIDFilter(12:00:00:00:00:00)
    -> filter_b::BSSIDFilter(12:00:00:00:00:01)
    -> filter_c::BSSIDFilter(12:00:00:00:00:02)
    -> post_capt_cnt::Counter()
    -> assoc::AssocTracker()
    -> SetPacketType(HOST)
    -> Paint(99, ANNO 27)  // set TTL
    -> wifi_ol::WifiOverlay(COORDINATOR www.citysense.net, LOCAL_IP 192.168.144.1,
                            TRACKER assoc, STICKY_ROUTES true, LOGGING INFO)
    -> rtr::LinearIPLookup(0.0.0.0/32 0, 0.0.0.0/0 1);

// unclassified
rtr[0] -> unclassified::Counter()
    -> RadiotapEncap()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 140, NUMBER true,
            DETAILED true, TIMESTAMP true)
    -> Discard;

// all others
rtr[1] -> Discard;
