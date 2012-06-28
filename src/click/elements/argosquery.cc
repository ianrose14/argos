/*
 * argosquery.{cc,hh} -- notifies other elements about query's priority levels
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "argosquery.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include "argos/anno.h"
CLICK_DECLS


ArgosQuery::ArgosQuery()
{
    // sanity check - make sure anno.h makes sense
    assert(sizeof(struct argos_sniff) == ARGOS_SNIFF_ANNO_SIZE);
    assert(sizeof(struct argos_ctrl) == ARGOS_CTRL_ANNO_SIZE);
}

ArgosQuery::~ArgosQuery()
{
}

int
ArgosQuery::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int parsed = cp_va_kparse(conf, this, errh,
        "QUERY", cpkM, cpString, &_query,
        "PRIORITY", cpkM, cpByte, &_priority,
        cpIgnoreRest, cpEnd);
    if (parsed < 0)
        return -1;

    for (int i=parsed; i < conf.size(); i++) {
        String val;
        if (cp_va_kparse(conf[i], this, errh, "HANDLER", cpkP+cpkM, cpString, &val,
                cpIgnoreRest, cpEnd) < 0)
            return -1;
        _handler_names.push_back(val);
    }

    return 0;
}

int
ArgosQuery::initialize(ErrorHandler *errh)
{
    String args = _query + " " + String((int)_priority);

    for (int i=0; i < _handler_names.size(); i++) {
        Element *elt;
        const Handler *handler;
        if (cp_handler(_handler_names[i], Handler::OP_WRITE, &elt, &handler,
                this, errh) == false)
            return -1;
    
        int rv = handler->call_write(args, elt, errh);
        if (rv < 0) return rv;
    }

    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ArgosQuery)
