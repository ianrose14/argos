from_pcap::FromDump(-, STOP true)
    -> ToRotatingDump(FILENAME "rot-dump-test.pcap", DIR rot-test-dir,
                      DLT IEEE802_11_RADIO, MAXFILES 7)
    -> Discard;
