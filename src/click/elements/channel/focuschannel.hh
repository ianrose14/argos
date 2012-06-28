#ifndef CLICK_FOCUSCHANNEL_HH
#define CLICK_FOCUSCHANNEL_HH
#include <clicknet/wifi.h>
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/ewma.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include "../loghandler.hh"
#include "../wifimerge/wifimerge.hh"
CLICK_DECLS

/*
=c
FocusChannel()

=s Argos

WifiMerge packets pass through to learn the relationship of:
  [MAC address] -->  map{sniffer --> fidelity}
(for efficiency, maybe just track APs, not all stations)

Apps define a custom detector module that feeds off the raw tap.  When an event
for a MAC X is detected, call channel_focus handler on wifioverlay with args of
<MAC> and <THRESH> where thresh is the minimum fidelity criteria for selecting
which sniffers to focus.  (i.e. THRESH=0 selects all sniffers in the network)

WifiOverlay sends the handler request to the home-node for MAC X.  The
WifiOverlay on that node then calls the "get_sniffers <MAC> <THRESH>" handler of
FocusChannel to get a list of who needs to have their channel changed.
handler_write requests are sent to all nodes that meet the filter.

To estimate fidelity, we use beacon sequence numbers.  Is this reasonable?
Perhaps an experiment is in order where we send a bunch of traffic (maybe
manually varying the data rates, and maybe varying # of packets per second) from
a citymd node (tcpdump to capture all outgoing traffic), using the rest of the
network to capture traffic.  Then each node calculates its (estimated) fidelity
from the beacons that it captured and compares that to the the actual fidelity
that we can obtain from comparing tcpdump files.  This can all be done offline
with tcpdump files!  Also, we might want to do multiple calculations per
sniffer, e.g. 1 comparison per data rate (estimation might be better for lower
data rates).

note: might need to re-enabled high/low priority queues in WifiOverlay for
latency purposes.  ONLY DO THIS IF LATENCY IN EVAL LOOKS BAD.

*/

class SnifferMap {
public:
    SnifferMap() {}
    ~SnifferMap() {}

    void beacon_capture(int, int, struct argos_wifimerge_elt*);
    void get_sniffers(uint32_t, Vector<IPAddress>*);
    void update(Timestamp*);

    Timestamp last_packet;

private:
    // note: high scaling (lots of fractional bits) because values should never
    // be above 100 (we store values as percentages since they have to be ints,
    // so 100% fidelity is stored as 100)
    typedef DirectEWMAX<FixedEWMAXParameters<4, 16> > rate_t;

    struct FidelityStats {
        uint32_t _captured;  // beacons captured this interval
        uint32_t _bcn_ival;
        rate_t _rate;

        FidelityStats() {
            _captured = 0;
            _bcn_ival = 100;
        }

        FidelityStats(uint32_t beacon_interval) {
            _captured = 0;
            _bcn_ival = beacon_interval;
        }

        void add_capture() {
            _captured++;
        }

        void update(Timestamp *interval) {
            uint32_t msec = interval->msecval();
            uint32_t expected_bcn = (msec + _bcn_ival/2 /* rounding */) / _bcn_ival;

            if (_captured == (expected_bcn + 1)) {
                // this probably just means the timing was slightly off -
                // "rollover" one of the beacon captures to the next interval
                _captured = 1;
                _rate.update(1);
            }
            else if (_captured <= expected_bcn) {
                _captured = 0;
                uint32_t capt_perc = (_captured*100 + expected_bcn/2 /* rounding */)/expected_bcn;
                _rate.update(capt_perc);
            }
            else {
                assert(_captured > (expected_bcn + 1));
                click_chatter("warning.  captured = %u, expected = %u", _captured, expected_bcn);
                // do rollover like above and throw away the rest
                _captured = 1;
                _rate.update(1);
            }
        }
    };

    HashMap<IPAddress, FidelityStats> _sniffer_stats;
};

class FocusChannel : public Element {
public:
    FocusChannel();
    ~FocusChannel();

    const char *class_name() const	{ return "FocusChannel"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void run_timer(Timer*);
    Packet *simple_action(Packet*);

private:
    Timer _timer;
    Logger *_log;
    HashMap<EtherAddress, SnifferMap> _ap_map;
    Timestamp _timeout;
    Timestamp _interval;
};

CLICK_ENDDECLS
#endif
