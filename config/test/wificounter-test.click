from_pcap::FromDump(-, END_CALL s.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> CheckWifi()
    -> wifi_cnt::WifiCounter()
    -> Discard;

s::Script(TYPE PROXY,
    print $(sprintf "mgmt_pkts=%u mgmt_bytes=%u data_pkts=%u data_bytes=%u ctrl_pkts=%u ctrl_bytes=%u"
            $(wifi_cnt.mgmt_pkts) $(wifi_cnt.mgmt_bytes) $(wifi_cnt.data_pkts) $(wifi_cnt.data_bytes)
            $(wifi_cnt.ctrl_pkts) $(wifi_cnt.ctrl_bytes)),
    print $(sprintf "null_data_pkts=%u null_data_bytes=%u beacon_pkts=%u beacon_bytes=%u"
            $(wifi_cnt.null_data_pkts) $(wifi_cnt.null_data_bytes)
            $(wifi_cnt.beacon_pkts) $(wifi_cnt.beacon_bytes)),
    print $(sprintf "encrypted_pkts=%u encrypted_bytes=%u invalid_pkts=%u invalid_bytes=%u"
            $(wifi_cnt.encrypted_pkts) $(wifi_cnt.encrypted_bytes)
            $(wifi_cnt.invalid_pkts) $(wifi_cnt.invalid_bytes)),
    write wifi_cnt.reset,
    stop);
