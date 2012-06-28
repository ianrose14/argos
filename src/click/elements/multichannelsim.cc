/*
 * multichannelsim.{cc,hh} -- 
 * Ian Rose
 */

#include <click/config.h>
#include "multichannelsim.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <clicknet/radiotap.h>
#include <clicknet/wifi.h>
#include <unistd.h>

CLICK_DECLS

//
// Public Methods
//

MultiChannelSim::MultiChannelSim()
{
    _current_channel = 0;
    _dlt = DLT_IEEE802_11_RADIO;
    _limit = -1;
    _ps_recv = 0;
    _ps_drop = 0;
    _total_count = 0;
    _pkt_count = 0;
    _delayed_count = 0;
}

MultiChannelSim::~MultiChannelSim()
{
}

enum {
    H_KERN_RECV,
    H_KERN_DROP,
    H_DLT,
    H_ENCAP,
    H_RESET,
    H_SET_CHANNEL,
    H_GET_CHANNEL,
    H_DELAYED_PACKETS,
    H_TOTAL_PACKETS
};

void
MultiChannelSim::add_handlers()
{
    // emulate FromPcap
    add_read_handler("kernel_recv", read_handler, (void *)H_KERN_RECV);
    add_read_handler("kernel_drops", read_handler, (void *)H_KERN_DROP);
    add_read_handler("dlt", read_handler, (void *)H_DLT);
    add_read_handler("encap", read_handler, (void*)H_ENCAP);
    add_write_handler("reset", write_handler, (void*)H_RESET);

    // emulate WifiChannel
    add_read_handler("get_channel", read_handler, (void*)H_GET_CHANNEL);
    add_write_handler("set_channel", write_handler, (void*)H_SET_CHANNEL);

    // new stuff
    add_read_handler("delayed_packets", read_handler, (void*)H_DELAYED_PACKETS);
    add_read_handler("total_packets", read_handler, (void*)H_TOTAL_PACKETS);
}

int
MultiChannelSim::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "LIMIT", 0, cpInteger, &_limit,
            cpEnd) < 0)
	return -1;
    return 0;
}

int
MultiChannelSim::initialize(ErrorHandler *)
{
    // start on channel 1
    _current_channel = 1;

    return 0;
}

void
MultiChannelSim::push(int port, Packet *p)
{
    // we just got a packet - if its from the port that corresponds to the
    // channel we are currently "tuned" to, then process it normally; otherwise,
    // push it to the second output (if it exists)
    if (port != (int)(_current_channel - 1)) {
        checked_output_push(1, p);
        return;
    }

    if (_limit != -1) {
        if (_total_count == _limit) {
            p->kill();
            return;
        }
        assert(_total_count < _limit);
    }

    _total_count++;
    _pkt_count++;


    Timestamp now = Timestamp::now();
    Timestamp delay = now - p->timestamp_anno();
    if (delay > Timestamp::make_msec(10)) _delayed_count++;

    output(0).push(p);
}


//
// Private Methods
//

String
MultiChannelSim::read_handler(Element* e, void *thunk)
{
    const MultiChannelSim* elt = static_cast<MultiChannelSim*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_KERN_RECV: {
        return String(elt->_ps_recv);
    }
    case H_KERN_DROP: {
        return String(elt->_ps_drop);
    }
    case H_DLT: {
        return String(pcap_datalink_val_to_name(elt->_dlt));
    }
    case H_ENCAP:
        switch (elt->_dlt) {
        case DLT_EN10MB:
            return "ETHER";
        case DLT_IEEE802_11:
            return "802.11";
        case DLT_IEEE802_11_RADIO:
            return "802.11_RADIO";
        default:
            return "";
        }
    case H_GET_CHANNEL: {
        return String((int)elt->_current_channel);
    }
    case H_DELAYED_PACKETS: {
        return String(elt->_delayed_count);
    }
    case H_TOTAL_PACKETS: {
        return String(elt->_pkt_count);
    }
    default:
        return "internal error (bad thunk value)";
    }
}

int
MultiChannelSim::write_handler(const String &s_in, Element *e, void *thunk, ErrorHandler *errh)
{
    MultiChannelSim* elt = static_cast<MultiChannelSim*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET: {
        elt->_ps_recv = 0;
        elt->_ps_drop = 0;
        elt->_pkt_count = 0;
        elt->_delayed_count = 0;
        return 0;
    }
    case H_SET_CHANNEL: {
        u_int channel;
        if (!cp_integer(s_in, &channel))
            return -EINVAL;
        elt->_current_channel = (uint8_t)channel;
        return 0;
    }
    default:
        return errh->error("invalid thunk");
    }
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(MultiChannelSim)
ELEMENT_LIBS(-L../build/lib -lpcap)
