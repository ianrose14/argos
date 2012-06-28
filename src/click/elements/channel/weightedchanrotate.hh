#ifndef CLICK_WEIGHTEDCHANROTATE_HH
#define CLICK_WEIGHTEDCHANROTATE_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
WeightedChanRotate()

=s Argos

Rotates through 802.11 channels at a weighted time interval.

=d
Rotates through 802.11 channels at a weighted time interval.

*/

class WeightedChanRotate : public Element {
public:
    WeightedChanRotate();
    ~WeightedChanRotate();

    const char *class_name() const	{ return "WeightedChanRotate"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    inline bool get_active();
    int initialize(ErrorHandler*);
    void run_timer(Timer*);
    void set_active(bool);
    Packet *simple_action(Packet*);

protected:
    String channel_poll();
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

private:
    Logger *_log;

    bool _active;
    Timer _timer;

    uint32_t _period;
    uint32_t _min_interval;
    uint8_t _current_channel;
    Timestamp _chan_start;

    Vector<uint32_t> _counts;
    Vector<uint32_t> _intervals;
    Vector<uint32_t> _dwell_times;

    int _priority;
    String _setchan_handler_name;
    const Handler *_setchan_handler;
    Element *_setchan_element;
};

CLICK_ENDDECLS
#endif
