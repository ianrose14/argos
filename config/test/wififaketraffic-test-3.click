Script(print "This tests that data send-rates (at low rates) really are correct");

from_pcap::WifiFakeTraffic(LOC_X 0, LOC_Y 0,
                           GRID_WIDTH 0, GRID_LEN 0,
                           SETUP_SEED 11, TRAFFIC_SEED 10,
                           NUM_APS 100, CLIENTS_PER_AP 3,
                           AP_DATA_RATE 3,
                           HEADROOM 196, BUFFER 500000,
                           IMMEDIATE true,
                           SINGLE_CHANNEL 1);

from_pcap -> cnt::Counter()
    -> Discard;

Script(print "Packets per sec should be about 10*100 + 3*100 = 1300");

Script(wait 1,
       set msg $(sprintf "PCAP kern_recv=%u kern_drop=%u capt_pkts=%u capt_bytes=%u"
                 $(from_pcap.kernel_recv) $(from_pcap.kernel_drops)
                 $(cnt.count) $(cnt.byte_count)),
       print "$(msg)",
       write from_pcap.reset,
       write cnt.reset,
       loop);
