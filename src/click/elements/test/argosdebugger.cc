/*
 * argosdebugger.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "argosdebugger.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <unistd.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include "../argos/anno.h"  // for argos_sniff struct definition
#include "../loghandler.hh"
CLICK_DECLS


ArgosDebugger::ArgosDebugger()
    : _timer(this), _interval(0), _label(""), _mode(MODE_TIMESTAMP)
{
}

ArgosDebugger::~ArgosDebugger()
{
}

int
ArgosDebugger::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String mode = "";

    if (cp_va_kparse(conf, this, errh,
            "LABEL", cpkP, cpString, &_label,
            "MODE", 0, cpString, &mode,
            "INTERVAL", 0, cpTimestamp, &_interval,
            cpEnd) < 0)
        return -1;

    if (_label != "") _label += ": ";

    if (mode != "") {
        mode = mode.lower();
        if (mode == "timestamp")
            _mode = MODE_TIMESTAMP;
        else if (mode == "use_count")
            _mode = MODE_USE_COUNT;
        else if (mode == "owner")
            _mode = MODE_OWNER;
        else if (mode == "packet_chain")
            _mode = MODE_PKT_CHAIN;
        else if (mode == "packet_number")
            _mode = MODE_PKT_NUMBER;
        else
            return errh->error("MODE must be one of 'TIMESTAMP', 'USE_COUNT'"
                ", 'OWNER', 'PACKET_CHAIN', 'PACKET_NUMBER'");
    }

    return 0;
}

int
ArgosDebugger::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    if (_interval > Timestamp(0))
        _timer.schedule_after(_interval);
    
    return 0;
}

void
ArgosDebugger::run_timer(Timer*)
{
    _timer.reschedule_after(_interval);
}

Packet *
ArgosDebugger::simple_action(Packet *p)
{
    switch (_mode) {
    case MODE_TIMESTAMP:
        click_chatter("%sp=%p, ts=%s", _label.c_str(), p,
            p->timestamp_anno().unparse().c_str());
        break;
    case MODE_USE_COUNT:
        click_chatter("%sp=%p, use_count=%d", _label.c_str(), p, p->use_count());
        break;
    case MODE_OWNER:
        click_chatter("%sp=%p, owner=%s", _label.c_str(), p,
            p->owner() == NULL ? "NULL" : p->owner()->name().c_str());
        break;
    case MODE_PKT_CHAIN:
        click_chatter("%sp=%p, p.chain-next=%p, p.chain-prev=%p",
            _label.c_str(), p, p->chain_next(), p->chain_prev());
        break;
    case MODE_PKT_NUMBER:
        click_chatter("%spacet_number_anno=0x%08x", _label.c_str(),
            PACKET_NUMBER_ANNO(p));
        break;
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ArgosDebugger)
