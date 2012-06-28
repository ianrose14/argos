#ifndef CLICK_STATICCHANNEL_HH
#define CLICK_STATICCHANNEL_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
StaticChannel()

=s Argos

Sticks to a single 802.11 channel.

=d
Sticks to a single 802.11 channel.

*/

class StaticChannel : public Element {
public:
    StaticChannel();
    ~StaticChannel();

    const char *class_name() const	{ return "StaticChannel"; }
    const char *port_count() const	{ return PORTS_0_0; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    inline bool get_active();
    int initialize(ErrorHandler*);
    void run_timer(Timer*);
    void set_active(bool);

protected:
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

private:
    Logger *_log;
    bool _active;
    Timer _timer;
    Timestamp _interval;
    uint8_t _channel;
    int _priority;

    String _setchan_handler_name;
    const Handler *_setchan_handler;
    Element *_setchan_element;
};

CLICK_ENDDECLS
#endif
