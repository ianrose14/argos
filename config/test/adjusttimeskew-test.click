FromDump(/usr/home/ianrose/data/pcap-traces/simultaneous/md238-2sec/citymd001.pcap)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> SetSniffer(CHANNEL 1, SNIFFER 192.168.14.1)
    -> adj_skew::AdjustTimeSkew(WARMUP 0)
    -> TimestampSort()
    -> wifi_merge::WifiMerge()
    -> [1]adj_skew[1]
    -> Discard;

FromDump(/usr/home/ianrose/data/pcap-traces/simultaneous/md238-2sec/citymd005.pcap)
    -> RadiotapDecap()
    -> WifiStripFCS()
    -> SetSniffer(CHANNEL 1, SNIFFER 192.168.14.5)
    -> adj_skew;

loghandler::LogHandler() -> Discard;
sys::SystemInfo();

script::Script(wait 5,
               read adj_skew.dump_skews,
set msg $(sprintf "STATS host=%s in_count=%s out_merges=%s out_dupes=%s avg_merge=%s"
        $(sys.hostname) $(wifi_merge.in_count) $(wifi_merge.merged_out)
        $(wifi_merge.dupes_out) $(wifi_merge.avg_merge)),
write loghandler.log wifi_merge INFO "$(msg)",
set msg $(sprintf "STATUS host=%s packets=%s records=%s sendq=%s expireq=%s"
        $(sys.hostname) $(wifi_merge.packet_count) $(wifi_merge.record_count)
        $(wifi_merge.send_len) $(wifi_merge.expire_len)),
write loghandler.log wifi_merge INFO "$(msg)",
write wifi_merge.reset,
               loop);
