#ifndef CLICK_WIFICOUNTER_HH
#define CLICK_WIFICOUNTER_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
WifiCounter()

=s Argos

*/

class WifiCounter : public Element {
public:
    WifiCounter();
    ~WifiCounter();

    const char *class_name() const	{ return "WifiCounter"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const           { return "S0"; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet*);

private:
    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    // 802.11 types
    uint32_t _mgmt_count;
    uint32_t _mgmt_bytes;
    uint32_t _data_count;  // includes null and non-null data frames
    uint32_t _data_bytes;
    uint32_t _ctrl_count;
    uint32_t _ctrl_bytes;

    // selected 802.11 subtypes
    uint32_t _null_data_count;
    uint32_t _null_data_bytes;
    uint32_t _beacon_count;
    uint32_t _beacon_bytes;

    uint32_t _encr_count;
    uint32_t _encr_bytes;
};

CLICK_ENDDECLS
#endif
