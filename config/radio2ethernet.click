fd::FromDump(-, MMAP false, STOP true, ACTIVE false)
    -> RadiotapDecap()
    -> wifi_cl::Classifier(0/08%0c) // data frames
    -> check::CheckWifi()
    -> WifiDecap(STRICT true, ETHER true)
    -> ToDump(-, SNAPLEN 4096, ENCAP ETHER);

Script(goto okencap $(eq "$(fd.encap)" "802_11_RADIO"),
       write stopper.foo,
       error $(sprintf "unsupported fd.encap (%s)" $(fd.encap)),
       label okencap,
       write fd.active true,
       return);

stopper::Script(TYPE PROXY, wait 0.1, stop);
