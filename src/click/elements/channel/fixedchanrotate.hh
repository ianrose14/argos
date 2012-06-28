#ifndef CLICK_FIXEDCHANROTATE_HH
#define CLICK_FIXEDCHANROTATE_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
FixedChanRotate()

=s Argos

Rotates through 802.11 channels at a fixed time interval.

=d
Rotates through 802.11 channels at a fixed time interval.

*/

class FixedChanRotate : public Element {
public:
    FixedChanRotate();
    ~FixedChanRotate();

    const char *class_name() const	{ return "FixedChanRotate"; }
    const char *port_count() const	{ return PORTS_0_0; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    inline bool get_active();
    int initialize(ErrorHandler*);
    void run_timer(Timer*);
    void set_active(bool);

protected:
    String channel_poll();
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

private:
    Logger *_log;

    bool _active;
    bool _delayed;
    Timestamp _delay;

    Timer _timer;
    Timestamp _interval;  // how long to spend on each channel

    Timer _sync_timer;
    Timestamp _sync_interval;
    bool _synchronized;

    Vector<uint8_t> _hop_sequence;
    uint8_t _hop_index;
    int _priority;

    String _setchan_handler_name;
    const Handler *_setchan_handler;
    Element *_setchan_element;
};

CLICK_ENDDECLS
#endif
