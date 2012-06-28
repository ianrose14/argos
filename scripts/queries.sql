
-- note: for station_stats...
-- the "ibss" flag is on if (a) it sent any (non-null) IBSS data frames, or
--   (b) it sent any beacons with the IBSS capinfo flag enabled
-- the "ap" flag is on if (a) it sent any (non-null) FROM-DS data frames, or
--   (b) it sent any beacons (regardless of the IBSS capinfo flag)
-- the "client" flag is on if it sent any (non-null) TO-DS data frames

-- list of all networks that have been observed to operate in both IBSS and AP modes
select distinct ssid from bss_stats where bssid in (select distinct mac from station_stats where flags=6);

-- num non-ibss access points
select count(*) from bss_stats where is_ibss=0;

-- alternative that should have approx the same answer:
--  discrepancies might be explained if there are hidden (no beacon) APs that we
--  identified (for bss_stats) only through probe responses
select count(*) from (select distinct mac from station_stats where beacons > 0 and data_bytes >= 0 and flags=2) a;

-- "real" IBSS networks (meaning both beacons and data traffic was observed)
-- IMPORTANT: make sure there are not a lot of entries with the same SSID but
--  different BSSIDs as this might indicate one IBSS network with a BSSID that
--  is changing over time
select bssid, ssid, encryption_types from bss_stats
where bssid in ((select distinct mac from station_stats
where beacons > 0 and data_bytes > 0 and flags=6));

-- num ibss access points
-- would have been nice to save their BSSID so that we could confirm their
-- network in bss_stats...
select count(*) from (select distinct mac from station_stats where beacons > 0 and data_bytes > 0 and flags=6) a;

-- total BSSIDs; meaning count(non-ibss APs) + count(ibss networks)
select (select count(*) from bss_stats where is_ibss=0) +
 (select count(*) from bss_stats where bssid in (select distinct mac from station_stats
  where beacons > 0 and data_bytes > 0 and flags=6));

-- num non-ibss access points offering encryption
select count(*) from bss_stats where is_ibss=0 and encryption_types>0;

-- breakdown of above
select count(*), encryption_desc from bss_stats b, lu_encryptions e where is_ibss=0 and b.encryption_types>0
and (b.encryption_types & e.encryption_id) > 0 group by encryption_desc;

--- num ibss access points offering encryption
select ssid, bssid, encryption_types from bss_stats where bssid in
 (select distinct mac from station_stats where beacons > 0 and data_bytes > 0 and flags=6);

-- unique clients
select count(*) from (select distinct mac from station_stats where (flags & 2) = 0) a;

-- the above assumes that all flags=0 stations are clients; a stricter version
-- would be:
select count(*) from (select distinct mac from station_stats where (flags & 3) = 1) a;

-- total captured packets and bytes
select sum(filt_capt_packets), sum(filt_capt_bytes), max(timestamp), min(timestamp) from pcap_stats;
-- or
select sum(filt_capt_packets)/(1000*1000.0) Mpackets,
sum(filt_capt_bytes)/(1024*1024*1024.0) GiBytes,
max(timestamp), min(timestamp) from pcap_stats;
-- or
select sum(packets)/(1000*1000.0) Mpackets,
sum(bytes)/(1024*1024*1024.0) GiBytes, sum(data_bytes)/(1024*1024*1024.0) data_GiBytes,
sum(encrypt_data_bytes)/(1024*1024*1024.0) encr_data_GiBytes
from station_stats where capt_node_id is not null;

-- list the heavy hitters (with approx location)
select mac, max(capt_node_id) node_id, sum(packets) packets, sum(bytes) bytes,
sum(data_bytes) data_bytes, sum(encrypt_data_bytes) encr_data_bytes
from station_stats where capt_node_id is not null group by mac order by bytes desc limit 10;
-- or
select mac, max(capt_node_id) node_id, sum(packets)/(1000*1000.0) Mpackets,
sum(bytes)/(1024*1024*1024.0) GiBytes, sum(data_bytes)/(1024*1024*1024.0) data_GiBytes,
sum(encrypt_data_bytes)/(1024*1024*1024.0) encr_data_GiBytes
from station_stats where capt_node_id is not null group by mac order by GiBytes desc limit 10;

-- total captured bytes, less the top 1 sender
select sum(bytes) from station_stats where capt_node_id is not null
and mac not in (select mac from (select sum(bytes) s, mac
    from station_stats where capt_node_id is not null group by mac order by s desc limit 1) a);

-- percent of data bytes that were encrypted, less the top 1 sender
select sum(encrypt_data_bytes)/sum(data_bytes) from station_stats where capt_node_id is not null
and mac not in (select mac from (select sum(bytes) s, mac
    from station_stats where capt_node_id is not null group by mac order by s desc limit 1) a);

-- detailed list of all stations that node XXX has captured from
select mac, bit_or(flags), max(timestamp) - min(timestamp), sum(non_ctrl_packets) as pkts,
sum(inferred_packets) as infer, cast(sum(non_ctrl_packets) as real)/sum(inferred_packets) as pkt_rat
from station_stats where coalesce(inferred_packets, 0) > 0 and capt_node_id=XX
group by mac order by pkt_rat desc;

-- count of all stations that node XXX has captured & inferred only 1 packet from
select count(*) from (select mac, sum(inferred_packets) as infer from station_stats
where coalesce(inferred_packets, 0) > 0 and capt_node_id=XXX group by mac) a where a.infer=1;

-- count of all stations that node XXX has captured & inferred >1 packet from
select count(*) from (select mac, sum(inferred_packets) as infer from station_stats
where coalesce(inferred_packets, 0) > 0 and capt_node_id=6 group by mac) a where a.infer>1;

-- number of sources detected by each sniffer (since Argos started some
-- particular run)
select capt_node_id, count(*) c from (select distinct capt_node_id, mac from
station_stats where capt_node_id is not null and timestamp > '2010-04-06 13:45') foo
group by capt_node_id order by c desc;

-- number of APs that utilized non-standard channels:
select count(*) c from bss_stats where channels<>0 and bssid in
(select mac from station_stats where flags=2 group by mac having max(timestamp) - min(timestamp) > '1 day')
and channels not in (1, 32, 1024, 1025, 1056, 1057, 33);

-- number of APs that utilized only standard channels:
select count(*) c from bss_stats where channels<>0 and bssid in
(select mac from station_stats where flags=2 group by mac having max(timestamp) - min(timestamp) > '1 day')
and channels in (1, 32, 1024, 1025, 1056, 1057, 33);


--------------------------------------------------
-- Map-Reduce Model Parameters
--------------------------------------------------

-- average and median bytes/sec inferred over all stations, broken down by type
-- of station
select flags, count(*) cnt, avg(a.inf_bytes/a.dur), median(a.inf_bytes/a.dur) from (select mac,
bit_or(flags) flags, sum(duration_sec) dur, cast(sum(bytes)*sum(inferred_packets) as
real)/sum(packets) inf_bytes from station_stats where agg_node_id is not null
and inferred_packets is not null and mac <> '00:02:6f:23:d4:7a' group by mac) a group by flags order by flags;



--------------------------------------------------
-- Case Studies
--------------------------------------------------

-- breakdown of snort alerts
select count(*) cnt, sig_id, sig_rev, priority, message from snort_alerts
group by sig_id, sig_rev, priority, message order by priority asc, cnt desc;

-- most popular websites, counting only unique visitors
select count(*) as c, h from
       (select distinct src_mac, coalesce(http_host, cookie_domain) as h from web_requests) as a
        group by h order by c desc;

-- list of some buses (not incl boston_bus...)
select bssid, ssid from bss_stats where ssid like '%oach%' and ssid not like 'MBTA%'
and ssid not like 'Coach%_Box-%';

-- what networks has station XXXX associated with?
select min(w.timestamp) min_ts, max(w.timestamp) max_ts, station_mac, w.bssid, ssid
from wifi_associations w left outer join bss_stats b
on w.bssid=b.bssid where station_mac=XXX
group by station_mac, w.bssid, ssid
order by min_ts;

-- list all of station XXX's associations
select timestamp, w.bssid, ssid, is_ibss, capt_node_id from
wifi_associations w left outer join bss_stats b
on w.bssid=b.bssid where station_mac=XXX
order by timestamp;

-- users with most associations:
select a.station_mac, b.uniq, a.total, a.span, a.latest from
(select station_mac, count(*) total, max(timestamp) - min(timestamp) span,
max(timestamp) latest from wifi_associations group by station_mac) a,
(select station_mac, count(*) uniq from (select distinct station_mac, bssid
from wifi_associations) foo group by station_mac) b where a.station_mac=b.station_mac
order by total desc;

-- most diverse mobile users:
select a.station_mac, b.uniq, a.total, a.span, a.latest from
(select station_mac, count(*) total, max(timestamp) - min(timestamp) span,
max(timestamp) latest from wifi_associations group by station_mac) a,
(select station_mac, count(*) uniq from (select distinct station_mac, bssid
from wifi_associations) foo group by station_mac) b where a.station_mac=b.station_mac
order by uniq desc;

-- users with the greatest number of unique Probe Request SSIDs
select count(*) cnt, src_mac from (select distinct src_mac, bssid, ssid from wifi_probe_requests) a
group by src_mac having count(*) < 50 order by cnt desc limit 10;

-- these are the 5 clients that were selected for highlighting:
-- ('00:12:f0:cd:f1:93', '00:1b:63:c2:87:5b', '00:1a:73:4b:29:04', '00:19:7E:C1:61:88', '00:21:85:b7:5d:74')

-- same basic stats on these 5 clients' probe requests
select src_mac, min(timestamp), max(timestamp), count(*) from wifi_probe_requests
where src_mac in ('00:12:f0:cd:f1:93', '00:1b:63:c2:87:5b',
 '00:1a:73:4b:29:04', '00:19:7E:C1:61:88', '00:21:85:b7:5d:74') group by src_mac;

select src_mac, count(*) from (select distinct src_mac, ssid from wifi_probe_requests
 where src_mac in ('00:12:f0:cd:f1:93', '00:1b:63:c2:87:5b', '00:1a:73:4b:29:04',
 '00:19:7E:C1:61:88', '00:21:85:b7:5d:74')) foo group by src_mac;


-- do any of these 5 clients also appear in the other things we are tracking?

-- web_requests?
select * from web_requests where src_mac in ('00:12:f0:cd:f1:93', '00:1b:63:c2:87:5b',
 '00:1a:73:4b:29:04', '00:19:7E:C1:61:88', '00:21:85:b7:5d:74');

-- wifi_assocations?
select station_mac, count(*), min(timestamp), max(timestamp) from wifi_associations
where station_mac in ('00:12:f0:cd:f1:93', '00:1b:63:c2:87:5b', '00:1a:73:4b:29:04',
 '00:19:7E:C1:61:88', '00:21:85:b7:5d:74') group by station_mac;

-- snort alerts have to be done manually (parse the pcap files)


-- get counts (and fidelity) for "good" and "bad" coverage populations

-- APs
--
-- The "having sum(beacons) > 0" clause isn't necessary but its a bit odd to
-- count APs that we detected (from a non-beacon packet) but NEVER saw a beacon
-- from, as these APs could be configured oddly so as to not send beacons at all
-- (or they might not be APs at all!).  There are a handful of APs in the
-- database that this clause applies to, a few of which MUST be wonky because we
-- captured a lot of packets from them, but 0 beacons.
select count(*) cnt, poor_coverage, sum(bcns) bcns, sum(ibcns) ibcns, sum(bcns)/sum(ibcns) fidelity from
    (select mac, (sum(beacons) < 10) poor_coverage, sum(beacons) bcns, sum(inferred_beacons) ibcns
     from station_stats_trunc
     where inferred_beacons is not null
     and agg_node_id is not null
     group by mac having sum(beacons) > 0 and sum(inferred_beacons) > 0) a group by poor_coverage;

-- get a list of the APs that the "having sum(beacons) > 0" clause above excludes:
select mac, min(timestamp), max(timestamp), sum(inferred_beacons) ibcn, sum(packets) pkts
    from station_stats_trunc where inferred_beacons is not null and
    mac in (select distinct mac from station_stats_trunc where flags&2 = 2)
    group by mac having sum(beacons) = 0 and sum(inferred_beacons) > 0;

-- same as above, but excluding APs that might actually be IBSS nodes
select mac, min(timestamp), max(timestamp), sum(inferred_beacons) ibcn, sum(packets) pkts
    from station_stats_trunc where inferred_beacons is not null and
    mac in (select distinct mac from station_stats_trunc where flags&2 = 2) and
    mac not in (select distinct mac from station_stats_trunc where flags&4=4)
    group by mac having sum(beacons) = 0 and sum(inferred_beacons) > 0;

-- "bad coverage" population of clients
select count(*) cnt, poor_coverage, sum(pkts) pkts, sum(ipkts) ipkts, sum(pkts)/sum(ipkts) fidelity from
    (select mac, (sum(non_ctrl_packets) < 10) poor_coverage, sum(non_ctrl_packets) pkts, sum(inferred_packets) ipkts
     from station_stats_trunc
     where inferred_packets is not null
     and agg_node_id is not null
     group by mac having sum(beacons) = 0 and sum(inferred_beacons) = 0
     and sum(inferred_packets) > 0) a group by poor_coverage;

-- get stats on the timespan over which we heard from each "bad coverage" AP
select count(*) cnt, min(span) min_span, max(span) max_span, avg(span) avg_span from
    (select mac, (max(timestamp) - min(timestamp)) span
     from station_stats_trunc
     where inferred_beacons is not null
     and agg_node_id is not null
     group by mac having sum(beacons) < 10 and sum(beacons) > 0 and sum(inferred_beacons) > 0) a;

-- get stats on the timespan over which we heard from each "bad coverage" client
select count(*) cnt, min(span) min_span, max(span) max_span, avg(span) avg_span from
    (select mac, (max(timestamp) - min(timestamp)) span
     from station_stats_trunc
     where inferred_packets is not null
     and agg_node_id is not null
     group by mac having sum(beacons) = 0 and sum(inferred_beacons) = 0
     and sum(inferred_packets) > 0 and sum(non_ctrl_packets) < 10) a;

-- crude histogram of timespans over which we heard from each "bad coverage" AP
select count(*) cnt, (span < '5 minutes') lt_5_min, (span < '10 minutes') lt_10_min,
        (span < '1 hour') lt_1_hour, (span < '8 hours') lt_8_hours from
    (select mac, (max(timestamp) - min(timestamp)) span
     from station_stats_trunc
     where inferred_beacons is not null
     and agg_node_id is not null
     group by mac having sum(beacons) < 10 and sum(beacons) > 0 and sum(inferred_beacons) > 0) a
     group by lt_5_min, lt_10_min, lt_1_hour, lt_8_hours
     order by lt_5_min, lt_10_min, lt_1_hour, lt_8_hours;

-- crude histogram of timespans over which we heard from each "bad coverage" client
select count(*) cnt, (span < '5 minutes') lt_5_min, (span < '10 minutes') lt_10_min,
        (span < '1 hour') lt_1_hour, (span < '8 hours') lt_8_hours from
    (select mac, (max(timestamp) - min(timestamp)) span
     from station_stats_trunc
     where inferred_packets is not null
     and agg_node_id is not null
     group by mac having sum(beacons) = 0 and sum(inferred_beacons) = 0
     and sum(inferred_packets) > 0 and sum(non_ctrl_packets) < 10) a
     group by lt_5_min, lt_10_min, lt_1_hour, lt_8_hours
     order by lt_5_min, lt_10_min, lt_1_hour, lt_8_hours;

-- crude histogram of capture counts from "bad coverage" APs
select count(*) cnt, (c = 1) is_1, (c < 5) lt_5 from
    (select mac, sum(beacons) c
     from station_stats_trunc
     where inferred_beacons is not null
     and agg_node_id is not null
     group by mac having sum(beacons) < 10 and sum(beacons) > 0 and sum(inferred_beacons) > 0) a
     group by is_1, lt_5
     order by is_1, lt_5;

-- crude histogram of capture counts from "bad coverage" clients
select count(*) cnt, (c = 1) is_1, (c < 5) lt_5 from
    (select mac, sum(non_ctrl_packets) c
     from station_stats_trunc
     where inferred_packets is not null
     and agg_node_id is not null
     group by mac having sum(beacons) = 0 and sum(inferred_beacons) = 0
     and sum(inferred_packets) > 0 and sum(non_ctrl_packets) < 10) a
     group by is_1, lt_5
     order by is_1, lt_5;


-- calculate beacon- or packet-based fidelity on a per-sniffer basis

select capt_node_id, sum(beacons)/sum(inferred_beacons) beacon_fidelity,
  sum(beacons) beacons, sum(inferred_beacons) inferred_beacons
  from (select mac, capt_node_id, sum(beacons) beacons, sum(inferred_beacons) inferred_beacons
        from station_stats_new
        where mac <> '00:02:6f:23:d4:7a' and capt_node_id is not null
        group by mac, capt_node_id having sum(beacons) >= 10) a
        group by capt_node_id order by beacon_fidelity desc;

select capt_node_id, sum(packets)/sum(inferred_packets) packet_fidelity,
  sum(packets) packets, sum(inferred_packets) inferred_packets
  from (select mac, capt_node_id, sum(non_ctrl_packets) packets, sum(inferred_packets) inferred_packets
        from station_stats_new
        where mac <> '00:02:6f:23:d4:7a' and capt_node_id is not null
        and non_ctrl_packets is not null and inferred_packets is not null
        group by mac, capt_node_id having sum(non_ctrl_packets) >= 10) a
        group by capt_node_id order by packet_fidelity desc;
