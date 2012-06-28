loghandler::LogHandler();

client::NetworkProxy(DST localhost, PORT 10199);
server_a::NetworkProxyServer(PORT 10199) -> out_a_cnt::Counter() -> Discard;
server_b::NetworkProxyServer(PORT 10200) -> out_b_cnt::Counter() -> Discard;

RandomSeed(998);
RandomSource(64) -> rr::RoundRobinSched() -> in_cnt::Counter() -> client;
RandomSource(1080) -> [1]rr;
RandomSource(38723) -> [2]rr;

Script(print $(sprintf "client=%s:%d, server_a=0.0.0.0:%d, server_b=0.0.0.0:%d"
               $(client.dst_host) $(client.dst_port)
               $(server_a.port) $(server_b.port)),
       wait 10,
       write client.dst_port 10200,
       print $(sprintf "client = %s:%d" $(client.dst_host) $(client.dst_port)),
       wait 5,
       write client.dst_port 10201,
       print $(sprintf "client = %s:%d" $(client.dst_host) $(client.dst_port)),
       wait 5,
       write client.dst_host "www.citysense.net",
       write client.dst_port 10199,
       print $(sprintf "client = %s:%d" $(client.dst_host) $(client.dst_port)),
       wait 5,
       write client.dst_host "foopablel",
       print $(sprintf "client = %s:%d" $(client.dst_host) $(client.dst_port)),
       return);

Script(wait 1,
       set msg $(sprintf "in=%d  out_a=%d  out_b=%d"
                 $(in_cnt.count) $(out_a_cnt.count) $(out_b_cnt.count)),
       print "$(msg)",
       write in_cnt.reset,
       write out_a_cnt.reset,
       write out_b_cnt.reset,
       loop);
