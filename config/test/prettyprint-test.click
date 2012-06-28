fd::FromDump(-, MMAP false, STOP true, ACTIVE false) -> sw::Switch(0);

Script(write sw.switch 0,
       goto done $(eq "$(fd.encap)" "ETHER"),
       write sw.switch 1,
       goto done $(eq "$(fd.encap)" "802_11"),
       write sw.switch 2,
       goto done $(eq "$(fd.encap)" "802_11_RADIO"),
       print "unsupported ENCAP type",
       stop,
       label done,
       write fd.active true);

sw[0] -> PrettyPrint(DLT EN10MB, MAXLENGTH 256, NUMBER true, DETAILED true, TIMESTAMP true)
    -> Discard;

sw[1] -> PrettyPrint(DLT IEEE802_11, MAXLENGTH 256, NUMBER true, DETAILED true, TIMESTAMP true)
    -> Discard;

sw[2] -> PrettyPrint(DLT IEEE802_11_RADIO, MAXLENGTH 256, NUMBER true, DETAILED true, TIMESTAMP true)
    -> Discard;
