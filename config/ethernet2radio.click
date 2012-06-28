// have to write to an actual file (rather than '-') because other shit sometimes
// gets printed to stdout (like Packet::push warnings)
define($OUTFILE out.pcap);

fd::FromDump(-, ACTIVE false, MMAP false, STOP true)
    -> WifiEncap(MODE 2  /* access point to station */, BSSID 11:22:33:44:55:66)
    -> RadiotapEncap()
    -> ToDump($OUTFILE, SNAPLEN 4096, ENCAP 802_11_RADIO);

Script(goto okencap $(eq "$(fd.encap)" "ETHER"),
       write stopper.foo,
       error $(sprintf "unsupported fd.encap (%s)" $(fd.encap)),
       label okencap,
       print $(sprintf "writing to %s" $OUTFILE),
       write fd.active true,
       return);

stopper::Script(TYPE PROXY, wait 0.1, stop);
