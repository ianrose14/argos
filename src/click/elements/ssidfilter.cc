/*
 * ssidfilter.{cc,hh} -- selectively 802.11 management frames based on SSID
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "ssidfilter.hh"
#include <click/confparse.hh>
#include "wifiutil.hh"
CLICK_DECLS


SSIDFilter::SSIDFilter() : _ignore_case(false)
{
}

SSIDFilter::~SSIDFilter()
{
}

int
SSIDFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "SSID", cpkP+cpkM, cpString, &_ssid,
            "IGNORE_CASE", 0, cpBool, &_ignore_case,
            cpEnd) < 0)
        return -1;
    return 0;
}

Packet *
SSIDFilter::simple_action(Packet *p)
{
    String ssid;
    if (!wifi_parse_ssid(p->data(), p->length(), &ssid)) {
        // no SSID element found in packet - pass it along
        return p;
    }

    if (_ignore_case)
        ssid = ssid.lower();

    if (ssid == _ssid) {
        checked_output_push(1, p);
        return NULL;
    } else {
        return p;
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(WifiUtil)
EXPORT_ELEMENT(SSIDFilter)
