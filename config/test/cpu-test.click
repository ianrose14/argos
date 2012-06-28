loghandler::LogHandler();
sys::SystemInfo();

Script(wait 1,
       set msg $(sprintf "SYSINFO host=%s cpu_1=%s cpu_10=%s cpu_60=%s mem_total_kb=%s maxrss_kb=%s alloc_pkts=%s cnt=%d"
           $(sys.hostname) $(sys.cpu_1) $(sys.cpu_10) $(sys.cpu_60)
           $(idiv $(sys.mem_total) 1024) $(sys.max_rss) $(sys.alloc_packets) $(c.count)),
       write loghandler.log system INFO "$(msg)",
       write c.reset,
       loop);

RatedSource(\<0800>, 10, 500) -> c::Counter -> Discard;
