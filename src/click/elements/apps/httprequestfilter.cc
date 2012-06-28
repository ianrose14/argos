/*
 * httprequestfilter.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "httprequestfilter.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <pcap/pcap.h>
#include <pktparse.h>
#include "../pktparse_wrap.hh"
CLICK_DECLS

HttpRequestFilter::HttpRequestFilter()
    : _dlt(DLT_EN10MB), _verbose(false)
{
}

HttpRequestFilter::~HttpRequestFilter()
{
}

int
HttpRequestFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dlt_name = "EN10MB";

    if (cp_va_kparse(conf, this, errh,
            "DLT", 0, cpString, &dlt_name,
            "VERBOSE", 0, cpBool, &_verbose,
            cpEnd) < 0)
        return -1;

    _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
    if (_dlt < 0)
        return errh->error("bad datalink type");

    return 0;
}

Packet *
HttpRequestFilter::simple_action(Packet *p)
{
    struct packet pkt;
    if (pktparse_click_packet(p, _dlt, &pkt) == -1) {
        if (_verbose)
            click_chatter("%s: bad packet: %s", name().c_str(), pkt.errmsg);
        checked_output_push(1, p);
        return NULL;
    } else {
        if (pkt.tcp_hdr == NULL) {
            checked_output_push(1, p);
            return NULL;
        }

        struct http_request *req =
            pktparse_parse_http_request((char*)pkt.unparsed, pkt.unparsed_len);

        if (req == NULL) {
            checked_output_push(1, p);
            return NULL;
        } else {
            // valid HTTP request parsed (although we don't actually look at it)
            free(req);
            return p;
        }
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HttpRequestFilter)
ELEMENT_REQUIRES(PktParse)
