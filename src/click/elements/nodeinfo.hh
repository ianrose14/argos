#ifndef CLICK_NODEINFO_HH
#define CLICK_NODEINFO_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

/*
=c
NodeInfo()

=s Argos

Push a set header onto packets.

=d
Push a set header onto packets.

*/

#define ARGOS_NODEINFO_MERGED_ID 32767

class NodeInfo : public Element {
public:
    NodeInfo();
    ~NodeInfo();

    const char *class_name() const	{ return "NodeInfo"; }
    const char *port_count() const	{ return PORTS_0_0; }

    int configure(Vector<String>&, ErrorHandler*);
    int configure_phase() const         { return CONFIGURE_PHASE_FIRST; }

    inline static int32_t *query_node_id(IPAddress ip) { return _nodes_by_ip.findp(ip); }
    inline static int32_t *query_node_id(String host) { return _nodes_by_host.findp(host); }

private:
    static HashMap<String, int32_t> _nodes_by_host;
    static HashMap<IPAddress, int32_t> _nodes_by_ip;
};

CLICK_ENDDECLS
#endif
