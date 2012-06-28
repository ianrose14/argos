/*
 * uniqcounter.{cc,hh} -- keeps a running count of the number of unique
 * instances of the value of some packet offset
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "uniqcounter.hh"
#include <click/error.hh>
#include <click/confparse.hh>
CLICK_DECLS

UniqCounter::UniqCounter()
    : _count(0), _offset(0), _fieldlen(1), _filter_packets(false)
{
}

UniqCounter::~UniqCounter()
{
}

void
UniqCounter::reset()
{
    _count = 0;
    _uniqs.clear();
}

int
UniqCounter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "OFFSET", cpkP+cpkM, cpUnsigned, &_offset,
            "LEN", cpkP, cpByte, &_fieldlen,
            "FILTER", 0, cpBool, &_filter_packets,
            cpEnd) < 0)
        return -1;

    return 0;
}

Packet *
UniqCounter::simple_action(Packet *p)
{
    if (p->length() < (_offset + _fieldlen))
        return p;

    ByteString bs = ByteString(p->data() + _offset, _fieldlen);
    int *ptr = _uniqs.findp(bs);

    if (ptr == NULL) {
        _uniqs.insert(bs, 0);  // value (0) is meaningless
        _count++;
        _rate.update(1);
        return p;
    } else {
        if (_filter_packets) {
            p->kill();
            return NULL;
        } else {
            return p;
        }
    }
}

enum { H_COUNT, H_RATE, H_RESET };

String
UniqCounter::read_handler(Element *e, void *thunk)
{
    UniqCounter *c = (UniqCounter *)e;
    switch ((intptr_t)thunk) {
    case H_COUNT:
	return String(c->_count);
    case H_RATE:
        // I don't understand this next line; its copied from counter.cc
	c->_rate.update(0);	// drop rate after idle period
	return c->_rate.unparse_rate();
    default:
	return "<error>";
    }
}

int
UniqCounter::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    UniqCounter *c = (UniqCounter *)e;
    switch ((intptr_t)thunk) {
    case H_RESET:
	c->reset();
	return 0;
    default:
	return errh->error("<internal>");
    }
}

void
UniqCounter::add_handlers()
{
    add_read_handler("count", read_handler, (void *)H_COUNT);
    add_read_handler("rate", read_handler, (void *)H_RATE);
    add_write_handler("reset", write_handler, (void *)H_RESET, Handler::BUTTON);
    add_write_handler("reset_counts", write_handler, (void *)H_RESET, Handler::BUTTON | Handler::UNCOMMON);
}

ByteString::ByteString(const u_char *data, int len)
{
    _data = new u_char[len];
    _len = len;

    memcpy(_data, data, len);

    // precompute hashcode for speed
    _hashcode = 0;

    int trunclen = len/4;
    uint32_t *intptr = (uint32_t*)data;
    for (int i=0; i < trunclen; i++)
        _hashcode ^= intptr[i];

    // handle leftovers
    if ((len - 4*trunclen) == 1)
        _hashcode ^= data[0];
    else if ((len - 4*trunclen) == 2)
        _hashcode ^= data[0] + (data[1] << 8);
    else if ((len - 4*trunclen) == 3)
        _hashcode ^= data[0] + (data[1] << 8) + (data[2] << 16);
}

ByteString::ByteString(const ByteString &ba)
{
    _len = ba._len;
    _data = new u_char[_len];
    memcpy(_data, ba._data, _len);
    _hashcode = ba._hashcode;
}

ByteString::~ByteString()
{
    delete [] _data;
}

String
ByteString::unparse() const
{
    String str = String::make_garbage(2*_len + 1);

    if (char *x = str.mutable_c_str()) {
        for (int i=0; i < _len; i++)
            snprintf(x + i*2, 2*(_len-i)+1, "%02X", _data[i]);
    }
    return str;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(UniqCounter)
