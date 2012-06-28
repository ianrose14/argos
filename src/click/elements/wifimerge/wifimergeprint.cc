/*
 * wifimergeprint.{cc,hh} -- print Wifi-Merge header from front of packets.
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifimergeprint.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include "wifimerge.hh"  // for wifi-merge struct definitions
#include "../argos/anno.h"
CLICK_DECLS


WifiMergePrint::WifiMergePrint()
    : _compact(false), _detailed(false), _ctime(false)
{
}

WifiMergePrint::~WifiMergePrint()
{
}

int
WifiMergePrint::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "LABEL", cpkP, cpString, &_label,
            "COMPACT", 0, cpBool, &_compact,
            "DETAILED", 0, cpBool, &_detailed,
            "CTIME", 0, cpBool, &_ctime,
            cpEnd) < 0)
        return -1;

    if (_label != "") _label += ": ";

    return 0;
}

Packet *
WifiMergePrint::simple_action(Packet *p)
{
    if (p->length() < sizeof(struct argos_wifimerge))
        // bad packet
        return p;

    struct argos_wifimerge *wf = (struct argos_wifimerge*)p->data();

    size_t reqlen = sizeof(struct argos_wifimerge) +
        wf->num_elts*sizeof(struct argos_wifimerge_elt);

    if (p->length() < reqlen)
        // bad packet
        return p;

    if (wf->magic != ARGOS_WIFIMERGE_MAGIC)
        // bad packet
        return p;

    // good packet
    String dupestr = "";
    if (wf->flags & ARGOS_WIFIMERGE_ISDUPE) dupestr = " (DUPE)";

    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    const struct argos_sniff *sniff = (const struct argos_sniff *)anno_ptr;

    struct argos_wifimerge_elt *elts = (struct argos_wifimerge_elt*)
        (p->data() + sizeof(struct argos_wifimerge));

    if (_compact) {
        StringAccum sa;
        for (int i=0; i < wf->num_elts; i++)
            sa << " " << IPAddress(elts[i].src);
        click_chatter("%s%s", _label.c_str(), sa.take_string().c_str());
    } else {
        click_chatter("%s%hu packet(s) merged (channel %hhu)%s", _label.c_str(),
            wf->num_elts, sniff->channel, dupestr.c_str());

        if (_detailed) {
            for (int i=0; i < wf->num_elts; i++) {
                String time_desc;
                if (_ctime) {
                    char cbuf[64];
                    ctime_r(&elts[i].ts.tv_sec, cbuf);
                    // chop off the trailing ' YYYY\n\0' portion and replace with
                    // just '\0'
                    cbuf[19] = '\0';
                    snprintf(cbuf + 19, sizeof(cbuf)-19, ".%06ld", elts[i].ts.tv_usec);
                    // lastly, chop off the 'DOW ' at the front
                    time_desc = String(cbuf + 4);
                } else {
                    time_desc = Timestamp(elts[i].ts).unparse();
                }

                click_chatter("    %s ~ channel %hhu, rssi %hhd, noise %hhd (%s)",
                    IPAddress(elts[i].src).unparse().c_str(), elts[i].channel,
                    elts[i].rssi, elts[i].noise, time_desc.c_str());
            }
        }
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiMergePrint)
