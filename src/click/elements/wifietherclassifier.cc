/*
 * wifietherclassifier.{cc,hh} -- selectively drop packets based on WifiEther
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "wifietherclassifier.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include "wifiutil.hh"
CLICK_DECLS


WifiEtherClassifier::WifiEtherClassifier()
{
}

WifiEtherClassifier::~WifiEtherClassifier()
{
}

int
WifiEtherClassifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (conf.size() != noutputs())
        return errh->error("need %d arguments, one per output port", noutputs());

    for (int i=0; i < conf.size(); i++) {
        if (conf[i] == "-") {
            if (i != (conf.size()-1))
                return errh->error("'-' must appear last in the parameter list");
            _patterns.push_back(-1);
        }
        else {
            int val;
            if (!cp_integer(conf[i], &val))
                return errh->error("expected integer or '-', not '%s'", conf[i].c_str());
            if ((val < 0) || (val >= (1<<16)))
                return errh->error("parameters must be >=0 and <= %d", (1<<16)-1);
            _patterns.push_back(val);
        }
    }
    return 0;
}

Packet *
WifiEtherClassifier::simple_action(Packet *p)
{
    int ethertype = -1;
    uint16_t eth;
    if (wifi_extract_ethertype(p->data(), p->length(), &eth) == 1)
        ethertype = eth;

    for (int i=0; i < _patterns.size(); i++) {
        if ((_patterns[i] == -1) || (_patterns[i] == ethertype)) {
            output(i).push(p);
            return NULL;
        }
    }

    p->kill();
    return NULL;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WifiEtherClassifier)
