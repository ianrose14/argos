/*
 * nodeinfo.{cc,hh} -- manages information on sniffer nodes in the network
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "nodeinfo.hh"
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS

// mojo required by C++ for static member variables
HashMap<String, int32_t> NodeInfo::_nodes_by_host;
HashMap<IPAddress, int32_t> NodeInfo::_nodes_by_ip;

NodeInfo::NodeInfo()
{
}

NodeInfo::~NodeInfo()
{
}

int
NodeInfo::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (int i=0; i < conf.size(); i++) {
        Vector<String> parts;
        cp_spacevec(conf[i], parts);
        if (parts.size() != 2)
            return errh->error("argument %d invalid; expected 'HOST ID' or 'IP ID'");
        int32_t node_id;
        if (!cp_integer(parts[1], 10, &node_id))
            return errh->error("argument %d invalid; expected 'HOST ID' or 'IP ID'");
        if (node_id == ARGOS_NODEINFO_MERGED_ID)
            return errh->error("%d is a reserved node-id (for 'merged')", node_id);
        IPAddress ip;
        if (cp_ip_address(parts[0], &ip, this))
            NodeInfo::_nodes_by_ip.insert(ip, node_id);
        else
            NodeInfo::_nodes_by_host.insert(parts[0], node_id);
    }

    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(NodeInfo)
