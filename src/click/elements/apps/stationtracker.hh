#ifndef CLICK_STATIONTRACKER_HH
#define CLICK_STATIONTRACKER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
#include "../db/postgresql.hh"
CLICK_DECLS

// since the seqnum field is only 12 bits, we use 0xFFFF as a reserved value to
// mean "uninitialized" (if no frames have been captured yet), ditto with 0xFF
// for TID variables
#define WIFI_SEQNUM_UNDEF 0xFFFF
#define WIFI_QOS_TID_UNDEF 0xFF

#define ARGOS_STATIONS_MSG_MAGIC 0x932bad03

// flag values to denote whether station is AP, client or IBSS
// **these must match database values!**
#define ARGOS_STATIONS_F_CLIENT  0x01  /* station acted as a client */
#define ARGOS_STATIONS_F_AP      0x02  /* station acted as an AP */
#define ARGOS_STATIONS_F_IBSS    0x04  /* station acted as an IBSS station */

/*
=c
StationTracker()

*/

class StationTracker : public Element {
public:
    StationTracker();
    ~StationTracker();

    const char *class_name() const	{ return "StationTracker"; }
    const char *port_count() const	{ return "1/0-2"; }
    const char *processing() const      { return PUSH; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet*);
    void run_timer(Timer*);

private:
    struct QoSCounter {
        QoSCounter() {
            for (int i=0; i < 16; i++) {
                last_seqnum[i] = WIFI_SEQNUM_UNDEF;
                last_seqnum_wnulls[i] = WIFI_SEQNUM_UNDEF;
            }
            last_qos_tid = WIFI_QOS_TID_UNDEF;
        }
        // I don't trust all cards/drivers to exactly implement the QoS spec
        // where it deals with QoS null data frames ("Sequence numbers for QoS
        // (+)Null frames may be set to any value") so we track two numbers; one
        // excluding null data frames and the other counting ALL data frames
        // (including nulls)
        uint16_t last_seqnum[16];
        uint16_t last_seqnum_wnulls[16];

        // TID value of the last (non-control) frame sent, or 0xFF if the last
        // frame was not QoS-enabled
        uint8_t last_qos_tid;
    };

    struct StationInfo {
        StationInfo() {
            last_seqnum = WIFI_SEQNUM_UNDEF;
            last_seqnum_wqos = WIFI_SEQNUM_UNDEF;
            qos_ignored_votes = 0;
            clear_stats();
            first_iteration = true;  // must set this AFTER clear_stats()
        }

        inline void clear_stats() {
            bcn_int = 0;
            packets = 0;
            bytes = 0;
            non_ctrl_packets = 0;
            inferred_packets = 0;
            data_bytes = 0;
            encr_data_bytes = 0;
            layer3_bytes = 0;
            beacons = 0;
            is_ibss = false;
            is_ap = false;
            is_client = false;
            first_iteration = false;
        }

        bool first_iteration;
        int bcn_int;  // only valid if >= 0
        uint64_t packets;
        uint64_t bytes;
        uint64_t non_ctrl_packets;
        uint64_t inferred_packets;
        uint64_t data_bytes;
        uint64_t encr_data_bytes;
        uint64_t layer3_bytes;
        uint64_t beacons;
        bool is_ibss, is_ap, is_client;

        // the last sequence number seen for non-QoS frames; according to the
        // spec this should include (i) all frames sent by non-QoS stations (or
        // non-QoS data frames sent by QoS stations), (ii) all management
        // frames, (iii) all broadcast/multicast QoS data frames
        uint16_t last_seqnum;

        // It appears that some APs do not follow the QoS spec (or I don't
        // understand it); they do not maintain separate counters per receiver
        // when sending QoS frames - to work around this we update 'last_seqnum'
        // only when we "should", according to the spec, but we update
        // 'last_seqnum_wqos' whenever a QoS or non-QoS frame it sent
        uint16_t last_seqnum_wqos;

        // Whether or not we think this station implements the above bad
        // behavior with regard to QoS frames; whenever it seems like it does,
        // we add 1, whenever it seems like it doesn't, we subtract one.  If the
        // value ever reaches 0x100 or -0x10 (note: these differ!) our decision
        // is made and we stop modifying it.
        int32_t qos_ignored_votes;

        HashMap<EtherAddress, QoSCounter> _qos_counters;
    };

    void db_insert(int32_t, bool, const EtherAddress&, uint32_t, uint32_t,
        const struct argos_stations_record*);
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    bool _am_server;
    int32_t _node_id;
    bool _merged;
    Timer _timer;
    Timestamp _interval;
    Timestamp _interval_start;
    Timestamp _first_pkt, _last_pkt;
    HashMap<EtherAddress, StationInfo*> _stations;
    PostgreSQL *_db;
    Logger *_log;
};

struct argos_stations_header {
    uint32_t magic;
    uint32_t node_id;
    uint8_t  is_merged;
    uint8_t  padding[3];
    uint32_t ts_sec;
    uint32_t duration_sec;
    uint32_t num_records;
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct argos_stations_record {
    uint8_t  mac[6];
    uint8_t  padding[2];
    uint64_t packets;
    uint64_t bytes;
    uint64_t non_ctrl_packets;
    uint64_t inferred_packets;
    uint64_t data_bytes;
    uint64_t encrypt_data_bytes;
    uint64_t layer3_bytes;
    uint16_t flags;
    uint8_t  padding2[2];
    uint64_t beacons;
    uint64_t inferred_beacons;
} CLICK_SIZE_PACKED_ATTRIBUTE;

CLICK_ENDDECLS
#endif
