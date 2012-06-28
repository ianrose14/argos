#ifndef CLICK_WIFIMERGE_HH
#define CLICK_WIFIMERGE_HH
#include <clicknet/wifi.h>
#include <click/dequeue.hh>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/list.hh>
#include <click/packet.hh>
#include <click/pair.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <click/timestamp.hh>
#include "../binheap.h"
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
WifiMerge()

=s Argos

Merges 802.11 frames from multiple sources.

=d
Merges 802.11 frames from multiple sources.

*/


/**************************************************************************/
/* Definitions for the header that the WifiMerge element pushed onto the */
/* front of packets that it outputs.                                      */
/**************************************************************************/

#define ARGOS_WIFIMERGE_MAGIC 0x80085555

struct argos_wifimerge {
    uint32_t magic;    /* used to confirm annotation contents */
    uint16_t num_elts;
    uint8_t flags;
    uint8_t unused_space[1];
    /* next follows [num_elts] argos_wifimerge_elt structs */
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct argos_wifimerge_elt {
    struct in_addr src;  // size = 4
    struct timeval ts;   // size = 8
    uint8_t channel;     // remainder = 4
    int8_t rssi;
    int8_t noise;
    uint8_t unused_space[1];
} CLICK_SIZE_PACKED_ATTRIBUTE;

/* flag values */
enum {
    ARGOS_WIFIMERGE_ISDUPE = 1,
};

/*
 * reuse the EXTRA_PACKETS annotation space for the TIMESKEW_ERR annotation
 * space; the value stored is in units of microseconds
 */
#define TIMESKEW_ERR_ANNO_OFFSET EXTRA_PACKETS_ANNO_OFFSET
#define TIMESKEW_ERR_ANNO_SIZE EXTRA_PACKETS_ANNO_SIZE
#define TIMESKEW_ERR_ANNO(p) EXTRA_PACKETS_ANNO(p)
#define SET_TIMESKEW_ERR_ANNO(p, v) SET_EXTRA_PACKETS_ANNO(p, v)

/*
 * Although the TIMESKEW_ERR annotation can hold a value up to ~4.3s, we impose
 * a (smaller) maximum value just to allow the WifiMerge element to be more
 * efficient when searching for packets to merge together (the smaller the max
 * timeskew error, the sooner a search can be stopped).
 */
#define MAX_TIMESKEW_ERR (250*1000)  /* usec */

/* Avoid using unrealistically small error values */
#define MIN_TIMESKEW_ERR 50  /* usec */

/*
 * In the very beginning, we don't have any data to use to estimate timeskew
 * errors, so we use this default as a guess.
 */
#define DEF_TIMESKEW_ERR (100*1000)  /* usec */

/*
 * Control frames have a much higher chance of collisions (i.e. 2 distinct
 * frames being sent with the exact same bits) within a short time frame, so we
 * enforce a smaller maximum timeskew-error.
 */
#define MAX_TIMESKEW_ERR_CTRL 300    /* usec */


/*********************************************************************/
/* Stuff relating to the WifiMerge element:                         */
/*********************************************************************/

#define WIFIMERGE_RSSI_THRESH 5

/*
 * WifiMergeRecord class
 */

class WifiMergeRecord {
public:
    // methods
    WifiMergeRecord(uint32_t, Timestamp);
    ~WifiMergeRecord();
    bool add_packet(Packet*);
    inline const Timestamp &expiration_time() const;
    inline uint32_t hash() const { return _hash; }
    inline bool is_empty() const { return (_pkt_list.begin() == _pkt_list.end()); }
    Packet *make_dupe_packet(Packet *);
    Packet *make_merged_packet(uint32_t*, uint32_t*);
    inline const Timestamp scheduled_output() const;
    uint32_t packet_count() const;
    inline void set_expiration(Timestamp &ts);

private:
    Timestamp _output_timeout;
    Timestamp _expiration;  // only meaningful if record is empty
    Timestamp _last_pkt_output;
    uint32_t _hash;

    // used to detect late-arriving packets, this is the upper bound of the
    // time-window of the last set of merged packets output from this list (set
    // to 0,0 if no packets have yet been output from this list)
    Timestamp _prev_upper_bound;

    struct PacketListNode {
        Packet *p;
        Timestamp received;
        List_member<PacketListNode> next;
        PacketListNode(Packet *pac) : p(pac) { };
        ~PacketListNode() {};
    };

    typedef List<PacketListNode, &PacketListNode::next> PacketList;
    PacketList _pkt_list;
};

inline const Timestamp&
WifiMergeRecord::expiration_time() const
{
    assert(is_empty());
    return _expiration;
}

inline const Timestamp
WifiMergeRecord::scheduled_output() const
{
    assert(!is_empty());
    return _pkt_list.begin().get()->received + _output_timeout;
}

inline void
WifiMergeRecord::set_expiration(Timestamp &ts)
{
    assert(is_empty());
    _expiration = ts;
}


/*
 * WifiMerge class
 */

class WifiMerge : public Element {
public:
    WifiMerge();
    ~WifiMerge();

    const char *class_name() const	{ return "WifiMerge"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PUSH; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet *);
    bool run_task(Task *);
    void run_timer(Timer *);

private:
    bool do_task_work(bool);
    bool send_next_merge(void);

    static uint32_t hash_packet(const Packet *);
    static String read_handler(Element *, void *);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    struct ExpirationTicket {
        Timestamp expiry;
        WifiMergeRecord *record;
        ExpirationTicket(WifiMergeRecord *r) {
            expiry = r->expiration_time();
            record = r;
        }
    };

    Task _task;
    Timer _timer;
    binheap_t *_sendq;  // WifiMergeRecord pointers sorted by scheduled_output()
    DEQueue<ExpirationTicket> _expireq; // ExpirationTickets sorted by expiry

    // how long to wait before a packet is output
    Timestamp _output_timeout;

    // how long to wait before a packet's record is garbage collected (once this
    // happens, duplicates of that packet will not be detectable)
    Timestamp _expire_timeout;

    uint32_t _mem_high_thresh;   // bytes
    uint32_t _mem_usage;         // bytes
    bool _mem_warning;

    HashMap<uint32_t, WifiMergeRecord*> _record_map;
    uint32_t _stored_packets;
    uint32_t _early_merges;
    uint32_t _merge_in_count, _merge_out_count;  // used to calculate average merge rate

    Logger *_log;

    // todo - delete all
public:
    static int32_t _net_allocs;
    static uint32_t _allocs;
};

CLICK_ENDDECLS
#endif
