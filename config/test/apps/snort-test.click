Script(TYPE SIGNAL INT, write snort.close, goto quit $(ne $? 0), exit, label quit, stop);
Script(TYPE SIGNAL PIPE, write snort.close, goto quit $(ne $? 0), exit, label quit, stop);
Script(TYPE SIGNAL TERM, write snort.close, goto quit $(ne $? 0), exit, label quit, stop);

fd::FromDump(-, MMAP false, END_CALL foo.bar, ACTIVE false) -> sw::Switch(0);
foo::Script(TYPE PROXY, print $(sprintf "dumpfile exhausted after %d packets" $(fd.count)), write fd.active false);

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

snort::Snort("aux/snort/bin/snort", CONF "config/snort/snort.conf",
             LOGDIR app-dumps/test/snort-logs/, ADDL_ARGS "-q -N",
             DLT EN10MB, SNAPLEN 1600, STOP true, LOGGING DATA);

pprint::PrettyPrint(DLT EN10MB, MAXLENGTH 256, NUMBER true, DETAILED true, TIMESTAMP true);

sw[0] -> q::Queue(10000) -> snort -> pprint -> Discard;
sw[1] -> WifiDecap(STRICT true, ETHER true) -> q;
sw[2] -> RadiotapDecap() -> WifiDecap(STRICT true, ETHER true) -> q;

q[1] -> Script(TYPE PACKET, print "warning: queue drop!") -> Discard;

Script(wait 1, goto done $(and $(eq $(fd.active) "false") $(eq $(q.length) 0)), loop, label done, write snort.close);
