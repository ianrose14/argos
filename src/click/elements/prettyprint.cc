/*
 * prettyprint.{cc,hh} -- pretty-print Argos pretty messages
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "prettyprint.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/wifi.h>
#include <pcap/pcap.h>
#include "pktparse_wrap.hh"
#include <pktparse-print.h>
CLICK_DECLS


PrettyPrint::PrettyPrint()
    : _count(0), _print_count(false), _print_timestamp(false), _print_fcs(false),
      _dlt(DLT_EN10MB), _maxlen(64), _detailed(false), _cbuf(NULL)
{
}

PrettyPrint::~PrettyPrint()
{
}

int
PrettyPrint::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dlt_name = "EN10MB";

    if (cp_va_kparse(conf, this, errh,
            "LABEL", cpkP, cpString, &_label,
            "MAXLENGTH", 0, cpInteger, &_maxlen,
            "DLT", 0, cpString, &dlt_name,
            "DETAILED", 0, cpBool, &_detailed,
            "NUMBER", 0, cpBool, &_print_count,
            "TIMESTAMP", 0, cpBool, &_print_timestamp,
            "FCS", 0, cpBool, &_print_fcs,
            cpEnd) < 0)
        return -1;

    // choose an arbitrarily "really big" value for the print buffer
    if (_maxlen < 0) _maxlen = 1024;

    _cbuf = (char*)malloc(_maxlen);
    if (_cbuf == NULL) return errh->error("malloc: %s", strerror(errno));

    _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
    if (_dlt < 0)
        return errh->error("bad datalink type");

    if (_label != "") _label += ": ";

    return 0;
}

Packet *
PrettyPrint::simple_action(Packet *p)
{
    _count++;

    String prefix;
    if (_print_count) {
        if (_label.length() > 0)
            prefix = String(_count) + " " + _label;
        else
            prefix = String(_count) + ": ";
    } else {
        prefix = _label;
    }

    snprintf(_cbuf, _maxlen, "[??]");  // in case nothing else is printed

    if (!print_packet(_cbuf, _maxlen, p, _dlt, _detailed, _print_fcs))
        snprintf(_cbuf, _maxlen, "[bad packet: %s]", _cbuf);

    String ts = "";
    if (_print_timestamp)
        ts = p->timestamp_anno().unparse() + ": ";
    click_chatter("%s%s%s", prefix.c_str(), ts.c_str(), _cbuf);

    return p;
}

bool
PrettyPrint::print_packet(char *str, size_t size, const Packet *p, int dlt,
    bool detailed, bool print_fcs)
{
    struct packet pkt;
    if (pktparse_click_packet(p, dlt, &pkt) < 0) {
        snprintf(str, size, "%s", pkt.errmsg);
        return false;
    }

    int flags = 0;
    if (detailed) flags |= PKTPARSE_PRINT_VERBOSE;
    if (print_fcs) flags |= PKTPARSE_PRINT_FCS;

    int rv = pktparse_print_full(str, size, &pkt, flags);
    if (rv < 0) {
        snprintf(str, size, "print failure: %s", strerror(errno));
        return false;
    }
    return true;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PrettyPrint)
ELEMENT_REQUIRES(PktParse)
