Script(print "This tests network events");

from_pcap::WifiFakeTraffic(LOC_X 0, LOC_Y 0,
                           GRID_WIDTH 0, GRID_LEN 0,
                           SETUP_SEED 11, TRAFFIC_SEED 10,
                           NUM_APS 2, CLIENTS_PER_AP 3, PATHLOSS 4,
                           AP_DATA_RATE 3,
                           HEADROOM 196, BUFFER 2048, 
                           IMMEDIATE true,
                           SINGLE_CHANNEL 1,
                           EVENT_ENABLED true, EVENT_DELAY 1, EVENT_DURATION 1,
                           EVENT_DATARATE 20, LIMIT 100);

from_pcap -> cnt::Counter()
    -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 140, NUMBER true, DETAILED true, TIMESTAMP true)
    -> Discard;
