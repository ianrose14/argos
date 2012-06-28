Script(print "This tests 2 different simultaneous sniffers");

from_pcap1::WifiFakeTraffic(LOC_X 0, LOC_Y 0,
                            GRID_WIDTH 5, GRID_LEN 5,
                            SETUP_SEED 11, TRAFFIC_SEED 10,
                            NUM_APS 6, CLIENTS_PER_AP 3, PATHLOSS 4,
                            AP_DATA_RATE 10,
                            HEADROOM 196, BUFFER 2048, 
                            IMMEDIATE true, LIMIT 100);

from_pcap2::WifiFakeTraffic(LOC_X 1.5, LOC_Y 1.5,
                            GRID_WIDTH 5, GRID_LEN 5,
                            SETUP_SEED 11, TRAFFIC_SEED 10,
                            NUM_APS 6, CLIENTS_PER_AP 3, PATHLOSS 4,
                            AP_DATA_RATE 10,
                            HEADROOM 196, BUFFER 2048, 
                            IMMEDIATE true, LIMIT 100);

from_pcap1 -> cnt1::Counter()
    -> ToDump(fake_1.pcap, USE_ENCAP_FROM from_pcap1)
    -> Discard;

from_pcap2 -> cnt2::Counter()
    -> ToDump(fake_2.pcap, USE_ENCAP_FROM from_pcap2)
    -> Discard;

Script(wait 10,
       set msg $(sprintf "PCAP1 kern_recv=%u kern_drop=%u capt_pkts=%u capt_bytes=%u"
                 $(from_pcap1.kernel_recv) $(from_pcap1.kernel_drops)
                 $(cnt1.count) $(cnt1.byte_count)),
       print "$(msg)",
       set msg $(sprintf "PCAP2 kern_recv=%u kern_drop=%u capt_pkts=%u capt_bytes=%u"
                 $(from_pcap2.kernel_recv) $(from_pcap2.kernel_drops)
                 $(cnt2.count) $(cnt2.byte_count)),
       print "$(msg)",
       write from_pcap1.reset,
       write cnt1.reset,
       write from_pcap2.reset,
       write cnt2.reset,
       loop
      );
