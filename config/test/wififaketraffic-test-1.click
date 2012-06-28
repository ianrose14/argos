Script(print "This is a basic test just to exercise things - it dumps packets to fake.pcap");

from_pcap::WifiFakeTraffic(LOC_X 0, LOC_Y 0,
                           GRID_WIDTH 1, GRID_LEN 1,
                           SETUP_SEED 4, TRAFFIC_SEED 5,
                           NUM_APS 3, CLIENTS_PER_AP 3, PATHLOSS 0.5,
                           HEADROOM 196, BUFFER 2048, 
                           IMMEDIATE true, LIMIT 15);


from_pcap -> capt_cnt::Counter()
    -> ToDump(fake.pcap, USE_ENCAP_FROM from_pcap)
    -> Discard;

Script(wait 10,
       set msg $(sprintf "kern_recv=%u kern_drop=%u capt_pkts=%u capt_bytes=%u"
                 $(from_pcap.kernel_recv) $(from_pcap.kernel_drops)
                 $(capt_cnt.count) $(capt_cnt.byte_count)),
       print "$(msg)",
       write from_pcap.reset,
       write capt_cnt.reset,
       loop
      );
