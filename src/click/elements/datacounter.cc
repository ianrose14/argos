/*
 * datacounter.{cc,hh} -- keeps a running sum of the values of some packet offset
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "datacounter.hh"
#include <click/error.hh>
#include <click/confparse.hh>
CLICK_DECLS

DataCounter::DataCounter()
    : _sum(0), _offset(0), _fieldlen(1), _big_endian(true)
{
}

DataCounter::~DataCounter()
{
}

void
DataCounter::reset()
{
    _sum = 0;
}

int
DataCounter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String byteorder;

    if (cp_va_kparse(conf, this, errh,
            "OFFSET", cpkP+cpkM, cpUnsigned, &_offset,
            "LEN", cpkP, cpByte, &_fieldlen,
            "BYTEORDER", cpkP, cpString, &byteorder,
            cpEnd) < 0)
        return -1;

    if ((_fieldlen <= 0) || (_fieldlen > 4))
        return errh->error("LEN must be > 0 and <= 4");

    byteorder = byteorder.lower();

    if ((byteorder == "little") || (byteorder == "little-endian"))
        _big_endian = false;
    else if ((byteorder == "big") || (byteorder == "big-endian"))
        _big_endian = true;
    else if ((byteorder == "net") || (byteorder == "network"))
        _big_endian = true;
    else if (byteorder == "host") {
        uint32_t foo = 1;
        u_char *ptr = (uint8_t*)(&foo);
        _big_endian = (ptr[3] == 1);
    }
    else {
        return errh->error("invalid BYTEORDER (expected BIG, LITTLE, NET or HOST)");
    }

    return 0;
}


Packet *
DataCounter::simple_action(Packet *p)
{
    if (p->length() < (_offset + _fieldlen))
        return p;

    const u_char *data = p->data();

    uint32_t val = 0;
    for (int i=0; i < _fieldlen; i++) {
        assert((_offset+i) < p->length());

        if (_big_endian) {
            val <<= 8;
            val += data[_offset+i];
        } else {
            val += (data[_offset+i] << (8*i));
        }
    }

    _sum += val;
    _rate.update(val);

    return p;
}


enum { H_SUM, H_RATE, H_RESET };

String
DataCounter::read_handler(Element *e, void *thunk)
{
    DataCounter *c = (DataCounter *)e;
    switch ((intptr_t)thunk) {
    case H_SUM:
	return String(c->_sum);
    case H_RATE:
        // I don't understand this next line; its copied from counter.cc
	c->_rate.update(0);	// drop rate after idle period
	return c->_rate.unparse_rate();
    default:
	return "<error>";
    }
}

int
DataCounter::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    DataCounter *c = (DataCounter *)e;
    switch ((intptr_t)thunk) {
    case H_RESET:
	c->reset();
	return 0;
    default:
	return errh->error("<internal>");
    }
}

void
DataCounter::add_handlers()
{
    add_read_handler("sum", read_handler, (void *)H_SUM);
    add_read_handler("rate", read_handler, (void *)H_RATE);
    add_write_handler("reset", write_handler, (void *)H_RESET, Handler::BUTTON);
    add_write_handler("reset_sums", write_handler, (void *)H_RESET, Handler::BUTTON | Handler::UNCOMMON);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DataCounter)
