#ifndef CLICK_TRAINTRACKER_HH
#define CLICK_TRAINTRACKER_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include "../loghandler.hh"
CLICK_DECLS

/*
=c
TrainTracker()

*/

class TrainTracker : public Element {
public:
    TrainTracker();
    ~TrainTracker();

    const char *class_name() const	{ return "TrainTracker"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    Packet *simple_action(Packet*);

private:
    HashMap<EtherAddress, String> _train_aps;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
