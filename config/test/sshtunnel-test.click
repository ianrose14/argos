define($CLIENT_PORT 10105);
define($SERVER_PORT 10106);

ssh::SSHTunnel($CLIENT_PORT, localhost, $SERVER_PORT, LOGIN ianrose@localhost, ID_FILE /usr/home/ianrose/.ssh/id_dsa, DELAY true);

Script(print "test 1",
       write logx.log test INFO "this is test 1",
       wait 5,
       write ssh.open,
       wait 5,
       print "test 2",
       write logx.log test INFO "this is test 2",
       wait 5,
       print "test 3",
       write logx.log test INFO "this is test 3",
       wait 5,
       print "test 4",
       write logx.log test INFO "this is test 4");

client::NetworkProxy(DST localhost, PORT $CLIENT_PORT);
logx::LogHandler() -> q::Queue() -> client;

server::NetworkProxyServer(PORT $SERVER_PORT) -> logx;
