
loghandler::LogHandler();

sim::WifiEventSim();
from_pcap::Script(TYPE PROXY, return $(sim.$0));
Script(write loghandler.log sim INFO "capturing from fake traffic");
chan_mgr::BasicChannelManager(sim.get_channel, sim.set_channel);

from_dump_1::FromDump(channel-event-pcaps/citysense263_ch1.pcap, TIMING true, MMAP false, END_CALL s_1.done);
from_dump_2::FromDump(channel-event-pcaps/citysense263_ch2.pcap, TIMING true, MMAP false, END_CALL s_2.done);
from_dump_3::FromDump(channel-event-pcaps/citysense263_ch3.pcap, TIMING true, MMAP false, END_CALL s_3.done);
from_dump_4::FromDump(channel-event-pcaps/citysense263_ch4.pcap, TIMING true, MMAP false, END_CALL s_4.done);
from_dump_5::FromDump(channel-event-pcaps/citysense263_ch5.pcap, TIMING true, MMAP false, END_CALL s_5.done);
from_dump_6::FromDump(channel-event-pcaps/citysense263_ch6.pcap, TIMING true, MMAP false, END_CALL s_6.done);
from_dump_7::FromDump(channel-event-pcaps/citysense263_ch7.pcap, TIMING true, MMAP false, END_CALL s_7.done);
from_dump_8::FromDump(channel-event-pcaps/citysense263_ch8.pcap, TIMING true, MMAP false, END_CALL s_8.done);
from_dump_9::FromDump(channel-event-pcaps/citysense263_ch9.pcap, TIMING true, MMAP false, END_CALL s_9.done);
from_dump_10::FromDump(channel-event-pcaps/citysense263_ch10.pcap, TIMING true, MMAP false, END_CALL s_10.done);
from_dump_11::FromDump(channel-event-pcaps/citysense263_ch11.pcap, TIMING true, MMAP false, END_CALL s_11.done);

from_dump_1 -> AdjustTimestamp() -> [0]sim;
from_dump_2 -> AdjustTimestamp() -> [1]sim;
from_dump_3 -> AdjustTimestamp() -> [2]sim;
from_dump_4 -> AdjustTimestamp() -> [3]sim;
from_dump_5 -> AdjustTimestamp() -> [4]sim;
from_dump_6 -> AdjustTimestamp() -> [5]sim;
from_dump_7 -> AdjustTimestamp() -> [6]sim;
from_dump_8 -> AdjustTimestamp() -> [7]sim;
from_dump_9 -> AdjustTimestamp() -> [8]sim;
from_dump_10 -> AdjustTimestamp() -> [9]sim;
from_dump_11 -> AdjustTimestamp() -> [10]sim;

s_1::Script(TYPE PROXY, print $(sprintf "%s channel 1 dumpfile expired" $(now)))
s_2::Script(TYPE PROXY, print $(sprintf "%s channel 2 dumpfile expired" $(now)))
s_3::Script(TYPE PROXY, print $(sprintf "%s channel 3 dumpfile expired" $(now)))
s_4::Script(TYPE PROXY, print $(sprintf "%s channel 4 dumpfile expired" $(now)))
s_5::Script(TYPE PROXY, print $(sprintf "%s channel 5 dumpfile expired" $(now)))
s_6::Script(TYPE PROXY, print $(sprintf "%s channel 6 dumpfile expired" $(now)))
s_7::Script(TYPE PROXY, print $(sprintf "%s channel 7 dumpfile expired" $(now)))
s_8::Script(TYPE PROXY, print $(sprintf "%s channel 8 dumpfile expired" $(now)))
s_9::Script(TYPE PROXY, print $(sprintf "%s channel 9 dumpfile expired" $(now)))
s_10::Script(TYPE PROXY, print $(sprintf "%s channel 10 dumpfile expired" $(now)))
s_11::Script(TYPE PROXY, print $(sprintf "%s channel 11 dumpfile expired" $(now)))

sim -> SetSniffer()  // sets all Argos-anno fields to 0                                                   
    -> chan_mgr
    -> capt_cnt::Counter()
    -> Discard;

Script(set c 0, label start, print $(sprintf "-------  Set-Channel %d  -------" $(add $c 1)),
       write sim.set_channel $(add $c 1), set c $(mod $(add $c 1) 11), wait 5, goto start);
