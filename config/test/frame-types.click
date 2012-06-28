from_dump::FromDump(-, END_CALL script.foo)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> capt_cnt::Counter()
    -> wifi_cl::Classifier(0/00%0c, 0/04%0c, 0/08%4c, 0/48%4c, -);

wifi_cl[0] -> mgmt_c::Counter() -> Discard;
wifi_cl[1] -> ctrl_c::Counter() -> Discard;
wifi_cl[2] -> data_nonnull_c::Counter() -> Discard;
wifi_cl[3] -> data_null_c::Counter() -> Discard;
wifi_cl[4] -> Script(TYPE PACKET, print "error: bad frame type!!") -> Discard;

script::Script(TYPE PROXY,
               set msg $(sprintf "capt_pkts=%u capt_bytes=%u"
                       $(capt_cnt.count) $(capt_cnt.byte_count)),
               print $(msg),
               set msg $(sprintf "FRAME-COUNTS mgmt=%s ctrl=%s data-null=%s data-nonnull=%s"
                         $(mgmt_c.count) $(ctrl_c.count) $(data_null_c.count) $(data_nonnull_c.count)),
               print $(msg),
               stop);
