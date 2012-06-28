-- source: comment #1 of http://www.postgresonline.com/journal/index.php?/archives/67-Build-Median-Aggregate-Function-in-SQL.html
CREATE OR REPLACE FUNCTION array_median(anyarray)
RETURNS anyelement AS
$$
SELECT CASE WHEN array_upper($1,1) = 0 THEN null ELSE asorted[ceiling(array_upper(asorted,1)/2.0)] END
FROM (SELECT ARRAY(SELECT ($1)[n] FROM
generate_series(1, array_upper($1, 1)) AS n
WHERE ($1)[n] IS NOT NULL
ORDER BY ($1)[n]
) As asorted) As foo ;
$$
LANGUAGE 'sql' IMMUTABLE;

CREATE AGGREGATE median(anyelement) (
SFUNC=array_append,
STYPE=anyarray,
FINALFUNC=array_median
);


----------------------------
-- Testing
----------------------------

DROP TABLE test;
CREATE TABLE test
(
    mystr text,
    myint integer,
    myreal real
);

----------------------------
-- Pcap performance
----------------------------

DROP TABLE pcap_stats;
CREATE TABLE pcap_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    kernel_recv bigint NOT NULL,
    kernel_drop bigint NOT NULL,
    mem_drop bigint NOT NULL,
    all_capt_packets bigint NOT NULL,
    all_capt_bytes bigint NOT NULL,
    filt_capt_packets bigint NOT NULL,
    filt_capt_bytes bigint NOT NULL
);

----------------------------
-- Network Usage
----------------------------

-- ol_in_proxy STATS (for the server only)
-- this table exists because on the server 1 socket receives data for multiple
-- WifiOverlay elements, so the receive stats need to be stored independently
DROP TABLE overlay_server_sockrecv;
CREATE TABLE overlay_server_sockrecv
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    net_recv_msgs integer NOT NULL,
    net_recv_bytes integer NOT NULL
);

-- wifi_ol_[testbed] STATS (for the server only)
DROP TABLE overlay_server_stats;
CREATE TABLE overlay_server_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    testbed text NOT NULL,
    total_routes integer NOT NULL
);

-- wifi_ol STATS (for sniffers only)
DROP TABLE overlay_sniffer_stats;
CREATE TABLE overlay_sniffer_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    total_routes integer NOT NULL,
    self_routes integer NOT NULL,
    no_route_packets integer NOT NULL,
    unclassified_packets integer NOT NULL,
    bcast_packets integer NOT NULL,
    waitq_dropped_msgs integer NOT NULL,
    waitq_dropped_bytes integer NOT NULL,
    ttl_dropped_msgs integer NOT NULL,
    ttl_dropped_bytes integer NOT NULL,
    from_self_packets integer NOT NULL,
    from_peers_packets integer NOT NULL,
    -- raw counts of messages and (compressed) bytes received by socket
    net_recv_msgs integer NOT NULL,
    net_recv_bytes integer NOT NULL
);

-- wifi_ol IN-STATS
-- used by both the server and sniffers
DROP TABLE overlay_peer_input_stats;
CREATE TABLE overlay_peer_input_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    peer_node_id smallint NOT NULL,
    recv_packets integer NOT NULL,
    recv_ctrl_msgs integer NOT NULL,
    recv_bytes integer NOT NULL
);

-- wifi_ol OUT-STATS
-- used by both the server and sniffers
DROP TABLE overlay_peer_output_stats;
CREATE TABLE overlay_peer_output_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    peer_node_id smallint NOT NULL,
    enqueued_packets integer NOT NULL,
    enqueued_ctrl_msgs integer NOT NULL,
    enqueued_bytes integer NOT NULL,
    enqueued_reroute_msgs integer NOT NULL,
    dropped_packets integer NOT NULL,
    dropped_ctrl_msgs integer NOT NULL,
    dropped_bytes integer NOT NULL,
    dequeued_msgs integer NOT NULL,
    sent_bytes integer NOT NULL,
    compress_rate real NOT NULL,  -- set to 0 if no bytes compressed
    avg_compress_size integer NOT NULL,  -- rounds to bytes
    avg_cpu real  -- may be NULL if cpu tracing is disabled
);

-- to_server OUT-STATS
DROP TABLE toserver_output_stats;
CREATE TABLE toserver_output_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    sent_msgs integer NOT NULL,
    sent_bytes integer NOT NULL,
    compress_rate real NOT NULL,  -- set to 0 if no bytes compressed
    avg_compress_size integer NOT NULL,  -- rounds to bytes
    avg_cpu real  -- may be NULL if cpu tracing is disabled
);

-- to_server STATS
DROP TABLE toserver_query_stats;
CREATE TABLE toserver_query_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    query text NOT NULL,
    dequeued_msgs integer NOT NULL,
    dequeued_bytes integer NOT NULL
);

-- queries STATS
DROP TABLE query_stats;
CREATE TABLE query_stats
(
    "timestamp" timestamp with time zone NOT NULL,
    duration_msec integer NOT NULL,
    node_id smallint NOT NULL,
    query text,
    in_packets integer NOT NULL,
    out_msgs integer NOT NULL,
    out_bytes integer NOT NULL,
    dropped_msgs integer NOT NULL
);


----------------------------
-- Traffic Statistics
----------------------------

DROP TABLE lu_nodes;
CREATE TABLE lu_nodes
(
    node_id smallint PRIMARY KEY,
    hostname text NOT NULL,
    testbed text
);

-- these values also appear in code; DON'T CHANGE THEM!
INSERT INTO lu_nodes VALUES (000, 'www.citysense.net', NULL);
INSERT INTO lu_nodes VALUES (001, 'citysense001', 'harvard');
INSERT INTO lu_nodes VALUES (002, 'citysense002', 'harvard');
INSERT INTO lu_nodes VALUES (003, 'citysense003', 'harvard');
INSERT INTO lu_nodes VALUES (004, 'citysense004', 'harvard');
INSERT INTO lu_nodes VALUES (005, 'citysense005', NULL);
INSERT INTO lu_nodes VALUES (006, 'citysense006', 'harvard');
INSERT INTO lu_nodes VALUES (007, 'citysense007', 'harvard');
INSERT INTO lu_nodes VALUES (010, 'citysense010', 'harvard');
INSERT INTO lu_nodes VALUES (011, 'citysense011', 'harvard');
INSERT INTO lu_nodes VALUES (012, 'citysense012', 'harvard');
INSERT INTO lu_nodes VALUES (259, 'citysense259', 'bbn');
INSERT INTO lu_nodes VALUES (261, 'citysense261', 'bbn');
INSERT INTO lu_nodes VALUES (262, 'citysense262', 'bbn');
INSERT INTO lu_nodes VALUES (263, 'citysense263', 'bbn');
INSERT INTO lu_nodes VALUES (264, 'citysense264', 'bbn');
INSERT INTO lu_nodes VALUES (266, 'citysense266', 'bbn');
INSERT INTO lu_nodes VALUES (268, 'citysense268', 'bbn');
INSERT INTO lu_nodes VALUES (270, 'citysense270', 'bbn');
INSERT INTO lu_nodes VALUES (271, 'citysense271', 'bbn');
INSERT INTO lu_nodes VALUES (273, 'citysense273', 'bbn');
INSERT INTO lu_nodes VALUES (274, 'citysense274', 'bbn');
INSERT INTO lu_nodes VALUES (275, 'citysense275', 'bbn');
INSERT INTO lu_nodes VALUES (276, 'citysense276', 'bbn');
INSERT INTO lu_nodes VALUES (513, 'citysense513', 'rowland');
INSERT INTO lu_nodes VALUES (514, 'citysense514', 'rowland');
INSERT INTO lu_nodes VALUES (769, 'citysense769', 'mystic');
INSERT INTO lu_nodes VALUES (770, 'citysense770', 'mystic');

-- reserved value:
INSERT INTO lu_nodes VALUES (32767, 'merged', NULL);

CREATE INDEX lu_nodes_id_idx ON lu_nodes (node_id);

-- BSSTracker will populate and update this
DROP TABLE bss_stats;
CREATE TABLE bss_stats
(
    bssid macaddr PRIMARY KEY,
    ssid text,
    -- boolean: have multiple SSID been observed for this BSS?
    ssid_changed smallint DEFAULT 0,
    -- boolean: have non-hidden SSIDs been observed in beacons for this BSS?
    ssid_in_beacons smallint DEFAULT 0,
    -- bitmask of advertised channels
    channels integer NOT NULL DEFAULT 0,
    -- NULL means "unknown" whereas 0 means "multiple values observed"
    bcn_int integer,
    is_ibss smallint,  -- boolean
    -- unicast encryption + key-management
    encryption_types smallint NOT NULL DEFAULT 0,
    group_cipher smallint NOT NULL DEFAULT 0,
    last_updated timestamp with time zone DEFAULT now()
);

-- populated on an interval by StationTracker
DROP TABLE station_stats;
CREATE TABLE station_stats
(
    capt_node_id smallint,
    agg_node_id smallint,
    mac macaddr NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    duration_sec smallint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL,
    non_ctrl_packets bigint,
    inferred_packets bigint,
    -- [encr_]data_bytes do not include NULL data frames
    data_bytes bigint NOT NULL,
    encrypt_data_bytes bigint NOT NULL,
    layer3_bytes bigint NOT NULL,
    flags smallint NOT NULL DEFAULT 0,
    beacon_ratio real, -- null for non-APs  (no longer used)
    beacons bigint NOT NULL,
    inferred_beacons bigint NOT NULL
);

-- possible indices
-- CREATE INDEX station_stats_mac_idx ON station_stats (mac);
-- CREATE INDEX station_stats_node_idx ON station_stats (node_id);
-- CREATE INDEX station_stats_bssid_idx ON station_stats (bssid);

DROP TABLE lu_station_flags;
CREATE TABLE lu_station_flags
(
    flag smallint PRIMARY KEY,
    flag_desc text NOT NULL
);

-- these values also appear in code; DON'T CHANGE THEM!
INSERT INTO lu_station_flags VALUES (01, 'acted as client');
INSERT INTO lu_station_flags VALUES (02, 'acted as access point');
INSERT INTO lu_station_flags VALUES (04, 'acted as IBSS');

-- each packet is attributed to only the "best" sniffer; they are not counted
-- multiple times for each capturing sniffer like they are in the station_stats
-- table
-- populated on an interval by WifiTrafficCounter (renamed from WifiCounter)
DROP TABLE wifi_traffic_types CASCADE;
CREATE TABLE wifi_traffic_types
(
    type_id smallint NOT NULL,
    subtype_id smallint NOT NULL,
    capt_node_id smallint,
    agg_node_id smallint,
    "timestamp" timestamp with time zone NOT NULL,
    duration_sec smallint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL
);

DROP TABLE lu_wifi_types;
CREATE TABLE lu_wifi_types
(
    type_id smallint,
    subtype_id smallint,
    type_desc text NOT NULL,
    PRIMARY KEY (type_id, subtype_id)
);

-- these values also appear in code; DON'T CHANGE THEM!
-- management frames
INSERT INTO lu_wifi_types VALUES (0, 0, 'Assocation Request');
INSERT INTO lu_wifi_types VALUES (0, 1, 'Assocation Response');
INSERT INTO lu_wifi_types VALUES (0, 2, 'Reassocation Request');
INSERT INTO lu_wifi_types VALUES (0, 3, 'Reassocation Response');
INSERT INTO lu_wifi_types VALUES (0, 4, 'Probe Request');
INSERT INTO lu_wifi_types VALUES (0, 5, 'Probe Response');
INSERT INTO lu_wifi_types VALUES (0, 8, 'Beacon');
INSERT INTO lu_wifi_types VALUES (0, 9, 'ATIM');
INSERT INTO lu_wifi_types VALUES (0, 10, 'Disassociation');
INSERT INTO lu_wifi_types VALUES (0, 11, 'Authentication');
INSERT INTO lu_wifi_types VALUES (0, 12, 'Deauthentication');
INSERT INTO lu_wifi_types VALUES (0, 13, 'Action');
-- control frames
INSERT INTO lu_wifi_types VALUES (1, 8, 'BlockACK Request');
INSERT INTO lu_wifi_types VALUES (1, 9, 'BlockACK');
INSERT INTO lu_wifi_types VALUES (1, 10, 'PS-Poll');
INSERT INTO lu_wifi_types VALUES (1, 11, 'RTS');
INSERT INTO lu_wifi_types VALUES (1, 12, 'CTS');
INSERT INTO lu_wifi_types VALUES (1, 13, 'Ack');
INSERT INTO lu_wifi_types VALUES (1, 14, 'CF-End');
INSERT INTO lu_wifi_types VALUES (1, 15, 'CF-End+CF-Ack');
-- data frames
INSERT INTO lu_wifi_types VALUES (2, 0, 'Data');
INSERT INTO lu_wifi_types VALUES (2, 1, 'Data+CF+Ack');
INSERT INTO lu_wifi_types VALUES (2, 2, 'Data+CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 3, 'Data+CF-Ack+CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 4, 'Null Data');
INSERT INTO lu_wifi_types VALUES (2, 5, 'CF-Ack');
INSERT INTO lu_wifi_types VALUES (2, 6, 'CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 7, 'CF-Ack+CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 8, 'QoS Data');
INSERT INTO lu_wifi_types VALUES (2, 9, 'QoS Data+CF+Ack');
INSERT INTO lu_wifi_types VALUES (2, 10, 'QoS Data+CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 11, 'QoS Data+CF-Ack+CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 12, 'QoS Null Data');
INSERT INTO lu_wifi_types VALUES (2, 13, 'QoS CF-Ack');
INSERT INTO lu_wifi_types VALUES (2, 14, 'QoS CF-Poll');
INSERT INTO lu_wifi_types VALUES (2, 15, 'QoS CF-Ack+CF-Poll');

CREATE VIEW wifi_traffic_types_desc
AS
SELECT type_desc, capt_node_id, agg_node_id, timestamp, duration_sec, packets, bytes
FROM lu_wifi_types lt, wifi_traffic_types tt
WHERE lt.type_id=tt.type_id AND lt.subtype_id=tt.subtype_id;


-- each packet is attributed to only the "best" sniffer; they are not counted
-- multiple times for each capturing sniffer like they are in the station_stats
-- table
-- populated on an interval by EtherTrafficCounter
DROP TABLE ether_traffic_types;
CREATE TABLE ether_traffic_types
(
    -- a NULL ethertype_id can be used as a catchall (e.g. to avoid growing this
    -- table too much in the odd event of that being a problem)
    ethertype_id int,
    capt_node_id smallint,
    agg_node_id smallint,
    "timestamp" timestamp with time zone NOT NULL,
    duration_sec smallint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL  -- actual payload bytes, not full 802.11 bytes
);

-- each packet is attributed to only the "best" sniffer; they are not counted
-- multiple times for each capturing sniffer like they are in the station_stats
-- table
-- populated on an interval by IPTrafficCounter
DROP TABLE ipproto_traffic_types;
CREATE TABLE ipproto_traffic_types
(
    -- a NULL ipproto_id can be used as a catchall (e.g. to avoid growing this
    -- table too much in the odd event of that being a problem)
    ipproto_id smallint,
    capt_node_id smallint,
    agg_node_id smallint,
    "timestamp" timestamp with time zone NOT NULL,
    duration_sec smallint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL  -- actual payload bytes, not full 802.11 bytes
);

-- each packet is attributed to only the "best" sniffer; they are not counted
-- multiple times for each capturing sniffer like they are in the station_stats
-- table
-- populated on an interval by UDPTrafficCounter
DROP TABLE udp_traffic_types;
CREATE TABLE udp_traffic_types
(
    -- port ranges are used to save space, although low_port can equal high_port
    -- to track single port numbers
    low_port int NOT NULL,
    high_port int NOT NULL,
    capt_node_id smallint,
    agg_node_id smallint,
    "timestamp" timestamp with time zone NOT NULL,
    duration_sec smallint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL  -- actual payload bytes, not full 802.11 bytes
);

-- each packet is attributed to only the "best" sniffer; they are not counted
-- multiple times for each capturing sniffer like they are in the station_stats
-- table
-- populated on an interval by TCPTrafficCounter
DROP TABLE tcp_traffic_types;
CREATE TABLE tcp_traffic_types
(
    -- port ranges are used to save space, although low_port can equal high_port
    -- to track single port numbers
    low_port int NOT NULL,
    high_port int NOT NULL,
    capt_node_id smallint,
    agg_node_id smallint,
    "timestamp" timestamp with time zone NOT NULL,
    duration_sec smallint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL  -- actual payload bytes, not full 802.11 bytes
);

DROP TABLE lu_encryptions;
CREATE TABLE lu_encryptions
(
    encryption_id smallint PRIMARY KEY,
    encryption_desc text NOT NULL
);

-- these values also appear in code; DON'T CHANGE THEM!
INSERT INTO lu_encryptions VALUES (00, 'none');
INSERT INTO lu_encryptions VALUES (01, 'WEP');
INSERT INTO lu_encryptions VALUES (02, 'TKIP');
INSERT INTO lu_encryptions VALUES (04, 'CCMP');
INSERT INTO lu_encryptions VALUES (08, 'PSK');
INSERT INTO lu_encryptions VALUES (16, '802.1X');
INSERT INTO lu_encryptions VALUES (256, 'vendor-specific');
INSERT INTO lu_encryptions VALUES (512, 'unknown');

----------------------------
-- Web Requests
----------------------------

-- populated with requests found by WebRequestTracker (renamed from UserWebTracker)
DROP TABLE web_requests;
CREATE TABLE web_requests
(
    -- timestamp should be the time of the first captured packet
    "timestamp" timestamp with time zone NOT NULL,
    capt_node_id smallint,
    src_mac macaddr NOT NULL,
    dst_port smallint,
    dst_ip inet NOT NULL,
    flags smallint NOT NULL DEFAULT 0,
    http_host text,
    cookie_domain text,
    search_queries text
);

DROP TABLE lu_web_requests_flags;
CREATE TABLE lu_web_requests_flags
(
    flag smallint PRIMARY KEY,
    flag_desc text NOT NULL
);

-- these values also appear in code; DON'T CHANGE THEM!
INSERT INTO lu_web_requests_flags VALUES (01, '>0 packets captured from request stream');
INSERT INTO lu_web_requests_flags VALUES (02, '>0 packets captured from response stream');
INSERT INTO lu_web_requests_flags VALUES (04, 'SYN captured from request stream');
INSERT INTO lu_web_requests_flags VALUES (08, 'first TCP data segment captured from request stream');
INSERT INTO lu_web_requests_flags VALUES (16, 'value of HTTP ''Host'' header from request stream');
INSERT INTO lu_web_requests_flags VALUES (32, 'value of HTTP ''Set-Cookie'' header from response stream');


----------------------------
-- Snort Alerts
----------------------------

-- populated with alerts from Snort
DROP TABLE snort_alerts;
CREATE TABLE snort_alerts
(
    "timestamp" timestamp with time zone NOT NULL,
    message text NOT NULL,
    sig_id integer NOT NULL,
    sig_rev integer NOT NULL,
    classification integer NOT NULL,
    priority integer NOT NULL,
    capt_node_id smallint,
    agg_node_id smallint
);

DROP TABLE snort_portscans;
CREATE TABLE snort_portscans
(
    "timestamp" timestamp with time zone NOT NULL,
    message text NOT NULL,
    sig_id integer NOT NULL,
    priority_count integer NOT NULL,
    connection_count integer NOT NULL,
    src_ip inet NOT NULL,
    ip_count integer NOT NULL,
    ip_range_low inet NOT NULL,
    ip_range_high inet NOT NULL,
    port_count integer NOT NULL,
    port_range_low integer NOT NULL,
    port_range_high integer NOT NULL,
    src_ether macaddr,
    capt_node_id smallint
);

GRANT SELECT ON snort_portscans TO argos;
GRANT INSERT ON snort_portscans TO argos;
REVOKE DELETE ON snort_portscans FROM ianrose;


----------------------------
-- Wifi Associations
---------------------------

-- populated with frames captured from AssocTracker
DROP TABLE wifi_associations;
CREATE TABLE wifi_associations
(
    "timestamp" timestamp with time zone NOT NULL,
    station_mac macaddr NOT NULL,
    bssid macaddr NOT NULL,
    capt_node_id smallint
);


----------------------------
-- Wifi ProbeRequests
---------------------------

-- populated with frames captured from ProbeRequestTracker
DROP TABLE wifi_probe_requests;
CREATE TABLE wifi_probe_requests
(
    "timestamp" timestamp with time zone NOT NULL,
    src_mac macaddr NOT NULL,
    bssid macaddr NOT NULL,
    ssid text,
    capt_node_id smallint,
    agg_node_id smallint
);


----------------------------
-- Wifi AP Channel Changes
----------------------------

-- populated with frames captured from APChannelTracker
DROP TABLE wifi_ap_channel_changes;
CREATE TABLE wifi_ap_channel_changes
(
    "timestamp" timestamp with time zone NOT NULL,
    ap macaddr NOT NULL,
    bssid macaddr NOT NULL,
    prev_chan smallint NOT NULL,
    new_chan smallint NOT NULL,
    capt_node_id smallint,
    agg_node_id smallint
);
