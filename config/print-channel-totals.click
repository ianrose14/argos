// argos_sniff starts at offset 40, channel field is 2 bytes into the annotation
define($CHANNEL_ANNO_OFFSET 42);
define($ARGOS_DEVNAME ath1);

wifi_chan::WifiChannel(DEVNAME $ARGOS_DEVNAME, INITIAL_CHAN 1, CHANGE_EUID true);
chan_mgr::BasicChannelManager(wifi_chan.get_channel, wifi_chan.set_channel);

//FixedChanRotate(HANDLER chan_mgr.lease_channel, INTERVAL 1, SYNCHRONIZE 300, PRIORITY 10);
wcr::WeightedChanRotate(HANDLER chan_mgr.lease_channel, PRIORITY 10, PERIOD 5, MIN_INTERVAL 0.1);

//FromDump("-", STOP true)
FromPcap(DEVNAME $ARGOS_DEVNAME, DLT IEEE802_11_RADIO, IMMEDIATE true, PROMISC true)
    -> RadiotapDecap()
    -> BSSIDFilter(12:00:00:00:00:00)
    -> BSSIDFilter(12:00:00:00:00:01)
    -> BSSIDFilter(12:00:00:00:00:02)
    -> cnt_all::Counter()
    -> WifiStripFCS()
    -> SetSniffer()
    -> assoc::AssocTracker()
    -> chan_mgr
    -> gc::GuessChannel(TRACKER assoc)
    -> tee::Tee()
    -> ps::PaintSwitch($CHANNEL_ANNO_OFFSET);

ps[0] -> cnt_0::Counter() -> Discard;
ps[1] -> cnt_1::Counter() -> Discard;
ps[2] -> cnt_2::Counter() -> Discard;
ps[3] -> cnt_3::Counter() -> Discard;
ps[4] -> cnt_4::Counter() -> Discard;
ps[5] -> cnt_5::Counter() -> Discard;
ps[6] -> cnt_6::Counter() -> Discard;
ps[7] -> cnt_7::Counter() -> Discard;
ps[8] -> cnt_8::Counter() -> Discard;
ps[9] -> cnt_9::Counter() -> Discard;
ps[10] -> cnt_10::Counter() -> Discard;
ps[11] -> cnt_11::Counter() -> Discard;

tee[1] -> Classifier(0/00%0c 0/80%f0)  // filter beacons
    -> bcn_cnt_all::Counter()
    -> ap_cnt_all::UniqCounter(10, 6)
    -> ps2::PaintSwitch($CHANNEL_ANNO_OFFSET);

new_ap::PrettyPrint("NEW AP", DLT IEEE802_11, MAXLENGTH 256, NUMBER true, DETAILED true, TIMESTAMP true) -> Discard;
ps2[0] -> ap_cnt_0::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[1] -> ap_cnt_1::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[2] -> ap_cnt_2::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[3] -> ap_cnt_3::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[4] -> ap_cnt_4::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[5] -> ap_cnt_5::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[6] -> ap_cnt_6::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[7] -> ap_cnt_7::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[8] -> ap_cnt_8::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[9] -> ap_cnt_9::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[10] -> ap_cnt_10::UniqCounter(10, 6, FILTER true) -> new_ap;
ps2[11] -> ap_cnt_11::UniqCounter(10, 6, FILTER true) -> new_ap;

// mgmt frames, non-null data frames
tee[2] -> wifi_cl::Classifier(0/00%0c, 0/08%4c) -> wcr -> Discard();
wifi_cl[1] -> wcr;

DriverManager(pause, write foo.bar);

Script(wait 5, write foo.bar, read chan_mgr.stats, write chan_mgr.reset, loop);

foo::Script(TYPE PROXY,
            print $(sprintf "total packets: %d, total beacons: %d, uniq APs: %d"
                    $(cnt_all.count) $(bcn_cnt_all.count) $(ap_cnt_all.count)),
            print $(sprintf "channel  0 - packets: %5d, uniq APs: %5d" $(cnt_0.count) $(ap_cnt_0.count)),
            print $(sprintf "channel  1 - packets: %5d, uniq APs: %5d" $(cnt_1.count) $(ap_cnt_1.count)),
            print $(sprintf "channel  2 - packets: %5d, uniq APs: %5d" $(cnt_2.count) $(ap_cnt_2.count)),
            print $(sprintf "channel  3 - packets: %5d, uniq APs: %5d" $(cnt_3.count) $(ap_cnt_3.count)),
            print $(sprintf "channel  4 - packets: %5d, uniq APs: %5d" $(cnt_4.count) $(ap_cnt_4.count)),
            print $(sprintf "channel  5 - packets: %5d, uniq APs: %5d" $(cnt_5.count) $(ap_cnt_5.count)),
            print $(sprintf "channel  6 - packets: %5d, uniq APs: %5d" $(cnt_6.count) $(ap_cnt_6.count)),
            print $(sprintf "channel  7 - packets: %5d, uniq APs: %5d" $(cnt_7.count) $(ap_cnt_7.count)),
            print $(sprintf "channel  8 - packets: %5d, uniq APs: %5d" $(cnt_8.count) $(ap_cnt_8.count)),
            print $(sprintf "channel  9 - packets: %5d, uniq APs: %5d" $(cnt_9.count) $(ap_cnt_9.count)),
            print $(sprintf "channel 10 - packets: %5d, uniq APs: %5d" $(cnt_10.count) $(ap_cnt_10.count)),
            print $(sprintf "channel 11 - packets: %5d, uniq APs: %5d" $(cnt_11.count) $(ap_cnt_11.count)),
            write cnt_0.reset,
            write cnt_1.reset,
            write cnt_2.reset,
            write cnt_3.reset,
            write cnt_4.reset,
            write cnt_5.reset,
            write cnt_6.reset,
            write cnt_7.reset,
            write cnt_8.reset,
            write cnt_9.reset,
            write cnt_10.reset,
            write cnt_11.reset,
            return 0);
