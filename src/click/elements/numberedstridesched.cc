/*
 * numberedstridesched.{cc,hh} -- stride scheduler that sets the packet number
 *                                annotation to the input it was pulled from
 * Ian Rose, Max Poletto, Eddie Kohler
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2003 International Computer Science Institute
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/packet_anno.hh>
#include "numberedstridesched.hh"
CLICK_DECLS

NumberedStrideSched::NumberedStrideSched()
{
}

NumberedStrideSched::~NumberedStrideSched()
{
}

Packet *
NumberedStrideSched::pull(int)
{
    // go over list until we find a packet, striding as we go
    Client *stridden = _list, *c;
    Packet *p = 0;
    for (c = _list; c && !p; c = c->_next) {
	if (c->_signal)
	    p = input(c - _all).pull();
	c->stride();

        // here is the addition from StrideSched:
        if (p) {
            SET_PACKET_NUMBER_ANNO(p, c - _all);
        }
    }

    // remove stridden portion from list
    if ((_list = c))
	c->_pprev = &_list;

    // reinsert stridden portion into list
    while (stridden != c) {
	Client *next = stridden->_next;
	stridden->insert(&_list);
	stridden = next;
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(NumberedStrideSched)
