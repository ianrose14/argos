/*
 * wificounter.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wificounter.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/wifi.h>
CLICK_DECLS


WifiCounter::WifiCounter()
    : _mgmt_count(0), _mgmt_bytes(0), _data_count(0), _data_bytes(0),
      _ctrl_count(0), _ctrl_bytes(0), _null_data_count(0), _null_data_bytes(0),
      _beacon_count(0), _beacon_bytes(0), _encr_count(0), _encr_bytes(0)
{
}

WifiCounter::~WifiCounter()
{
}

enum { H_MGMT_COUNT, H_MGMT_BYTES, H_DATA_COUNT, H_DATA_BYTES,
       H_CTRL_COUNT, H_CTRL_BYTES, H_NULL_DATA_COUNT, H_NULL_DATA_BYTES, 
       H_BEACON_COUNT, H_BEACON_BYTES, H_ENCR_COUNT, H_ENCR_BYTES,
       H_RESET };

void
WifiCounter::add_handlers()
{
    add_read_handler("mgmt_pkts", read_handler, (void*)H_MGMT_COUNT);
    add_read_handler("mgmt_bytes", read_handler, (void*)H_MGMT_BYTES);
    add_read_handler("data_pkts", read_handler, (void*)H_DATA_COUNT);
    add_read_handler("data_bytes", read_handler, (void*)H_DATA_BYTES);
    add_read_handler("ctrl_pkts", read_handler, (void*)H_CTRL_COUNT);
    add_read_handler("ctrl_bytes", read_handler, (void*)H_CTRL_BYTES);
    add_read_handler("null_data_pkts", read_handler, (void*)H_NULL_DATA_COUNT);
    add_read_handler("null_data_bytes", read_handler, (void*)H_NULL_DATA_BYTES);
    add_read_handler("beacon_pkts", read_handler, (void*)H_BEACON_COUNT);
    add_read_handler("beacon_bytes", read_handler, (void*)H_BEACON_BYTES);
    add_read_handler("encrypted_pkts", read_handler, (void*)H_ENCR_COUNT);
    add_read_handler("encrypted_bytes", read_handler, (void*)H_ENCR_BYTES);
    add_write_handler("reset", write_handler, (void*)H_RESET);
}

int
WifiCounter::configure(Vector<String> &, ErrorHandler *)
{
    return 0;
}

Packet *
WifiCounter::simple_action(Packet *p)
{
    const struct click_wifi *wifi = (const struct click_wifi *)p->data();

    uint8_t type = wifi->i_fc[0] & WIFI_FC0_TYPE_MASK;
    uint8_t subtype = wifi->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    switch (type) {
    case WIFI_FC0_TYPE_MGT:
        _mgmt_count++;
        _mgmt_bytes += p->length();
        if (subtype == WIFI_FC0_SUBTYPE_BEACON) {
            _beacon_count++;
            _beacon_bytes += p->length();
        }
        break;
    case WIFI_FC0_TYPE_DATA:
        _data_count++;
        _data_bytes += p->length();

        if ((subtype & WIFI_FC0_SUBTYPE_NODATA) == WIFI_FC0_SUBTYPE_NODATA) {
            _null_data_count++;
            _null_data_bytes += p->length();
        }

        if ((wifi->i_fc[1] & WIFI_FC1_WEP) == WIFI_FC1_WEP) {
            _encr_count++;
            _encr_bytes += p->length();
        }

        break;
    case WIFI_FC0_TYPE_CTL:
        _ctrl_count++;
        _ctrl_bytes += p->length();
        break;
    }

    return p;
}

String
WifiCounter::read_handler(Element* e, void *thunk)
{
    const WifiCounter* elt = static_cast<WifiCounter*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_MGMT_COUNT:
        return String(elt->_mgmt_count);
    case H_MGMT_BYTES:
        return String(elt->_mgmt_bytes);
    case H_DATA_COUNT:
        return String(elt->_data_count);
    case H_DATA_BYTES:
        return String(elt->_data_bytes);
    case H_CTRL_COUNT:
        return String(elt->_ctrl_count);
    case H_CTRL_BYTES:
        return String(elt->_ctrl_bytes);
    case H_NULL_DATA_COUNT:
        return String(elt->_null_data_count);
    case H_NULL_DATA_BYTES:
        return String(elt->_null_data_bytes);
    case H_BEACON_COUNT:
        return String(elt->_beacon_count);
    case H_BEACON_BYTES:
        return String(elt->_beacon_bytes);
    case H_ENCR_COUNT:
        return String(elt->_encr_count);
    case H_ENCR_BYTES:
        return String(elt->_encr_bytes);
    default:
        return "internal error (bad thunk value)";
    } 
}

int
WifiCounter::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    WifiCounter* elt = static_cast<WifiCounter*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET: {
        elt->_mgmt_count = 0;
        elt->_mgmt_bytes = 0;
        elt->_data_count = 0;
        elt->_data_bytes = 0;
        elt->_ctrl_count = 0;
        elt->_ctrl_bytes = 0;
        elt->_null_data_count = 0;
        elt->_null_data_bytes = 0;
        elt->_beacon_count = 0;
        elt->_beacon_bytes = 0;
        elt->_encr_count = 0;
        elt->_encr_bytes = 0;
        return 0;
    }
    default:
        return errh->error("invalid thunk");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiCounter)
