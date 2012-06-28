define($PORTNO 10807);
define($CLIENT_IP 192.168.14.1);

loghandler::LogHandler(LOGGING DATA);

netproxy::NetworkProxyServer(PORT $PORTNO)
    -> q::Queue()
    -> du::DelayUnqueue(0, UPDATE false)
    -> rs::RandomSample(1)
    -> lm::LifeMonitor(ERRORS true);

Script(wait 1,
       set lastping $(lm.last_ping $CLIENT_IP),
       set msg $(sprintf "%s --> latency: %s ms, last-ping: %s, count: %s drops: %s"
                 $CLIENT_IP $(lm.latency_ms $CLIENT_IP) $lastping $(lm.count $CLIENT_IP) $(lm.drops $CLIENT_IP)),
       write loghandler.log script DATA "$(msg)",
       goto begin $(eq $lastping 0),
       write lm.reset_counts $CLIENT_IP,
       loop);

Script(wait 20, print "starting to delay packets by 250ms...", write du.delay 0.25);

Script(wait 30, print "starting to drop 50% of packets...", write rs.sampling_prob 0.5);

Script(wait 40, print "resetting to default settings...", write du.delay 0, write rs.sampling_prob 1);
