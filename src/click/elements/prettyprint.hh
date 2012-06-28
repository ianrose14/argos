#ifndef CLICK_PRETTYPRINT_HH
#define CLICK_PRETTYPRINT_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
PrettyPrint()

=s Argos

Pretty prints a pretty message from an Argos sniffer.

=d
Pretty prints a pretty message from an Argos sniffer.

*/

class PrettyPrint : public Element {
public:
    PrettyPrint();
    ~PrettyPrint();

    const char *class_name() const	{ return "PrettyPrint"; }
    const char *flags() const           { return "S0"; }
    const char *port_count() const	{ return PORTS_1_1; }

    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet*);

    static bool print_packet(char*, size_t, const Packet*, int, bool, bool);

private:
    int _count;
    bool _print_count;      // prefix packets with an index number?
    bool _print_timestamp;  // prefix packets with their timestamp?
    bool _print_fcs;        // print packets' FCS value? (for ethernet/wifi)
    int _dlt;
    int _maxlen;
    String _label;
    bool _detailed;   // print detailed packet descriptions?
    char *_cbuf;
};

CLICK_ENDDECLS
#endif
