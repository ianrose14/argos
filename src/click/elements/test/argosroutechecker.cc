/*
 * argosroutechecker.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "argosroutechecker.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <unistd.h>
#include <sys/signal.h>
CLICK_DECLS


ArgosRouteChecker::ArgosRouteChecker()
    : _log(NULL)
{
}

ArgosRouteChecker::~ArgosRouteChecker()
{
}

int
ArgosRouteChecker::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";
    Element *router_elt = NULL, *tracker_elt = NULL;

    if (cp_va_kparse(conf, this, errh,
            "ROUTER", cpkM, cpElement, &router_elt,
            "TRACKER", cpkM, cpElement, &tracker_elt,
            "LOGGING", 0, cpString, &loglevel,
            "NETLOG", 0, cpString, &netlog,
            "LOGGER", 0, cpString, &logelt,
            cpEnd) < 0)
        return -1;

    // create log before anything else
    _log = LogHandler::get_logger(this, NULL, loglevel.c_str(), netlog.c_str(),
        logelt.c_str(), errh);
    if (_log == NULL)
        return -EINVAL;

    // check that router_elt is a pointer to an WifiOverlay element
    _router = (WifiOverlay*)router_elt->cast("WifiOverlay");
    if (_router == NULL)
        return errh->error("ROUTER element is not an WifiOverlay");

    // check that tracker_elt is a pointer to an AssocTracker element
    _assoc_tracker = (AssocTracker*)tracker_elt->cast("AssocTracker");
    if (_assoc_tracker == NULL)
        return errh->error("TRACKER element is not an AssocTracker");

    return 0;
}

Packet *
ArgosRouteChecker::simple_action(Packet *p)
{
    IPAddress src = MISC_IP_ANNO(p);

    EtherAddress bssid;
    if (_assoc_tracker->infer_bssid(p, &bssid) == false) {
        // failed to determine BSSID of packet; this shouldn't happen in this
        // element
        _log->error("infer_bssid failed on packet from %s (ts=%s)",
            src.unparse().c_str(), p->timestamp_anno().unparse().c_str());

        Packet *q = p->clone();
        if (q) checked_output_push(1, q);
        return p;
    }

    IPAddress *owner = _router->lookup_mapping(bssid);
    if (owner == NULL) {
        _log->error("lookup_mapping failed on packet from %s (bssid=%s, ts=%s)",
            src.unparse().c_str(), bssid.unparse_colon().c_str(),
            p->timestamp_anno().unparse().c_str());

        Packet *q = p->clone();
        if (q) checked_output_push(1, q);
        return p;
    }

    if (src != *owner) {
        _log->error("wrong sender on packet from %s (owner=%s, bssid=%s, ts=%s)",
            src.unparse().c_str(), owner->unparse().c_str(),
            bssid.unparse_colon().c_str(), p->timestamp_anno().unparse().c_str());

        Packet *q = p->clone();
        if (q) checked_output_push(1, q);
        return p;
    }

    // all is well!
    _log->debug("correct sender on packet from %s (bssid=%s, ts=%s)",
        src.unparse().c_str(), bssid.unparse_colon().c_str(),
        p->timestamp_anno().unparse().c_str());
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ArgosRouteChecker)
