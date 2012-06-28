define($PORTNO 10807);

loghandler::LogHandler(LOGGING DATA);

lm::LifeMonitor(INTERVAL 0.1, ERRORS true)
    -> SetPacketType(FASTROUTE)
    -> Queue()
    -> netproxy::NetworkProxy(DST 192.168.128.254, PORT $PORTNO, LOCAL_IP 192.168.14.1);

Script(print "started!");
