/*
 * comparepairs.{cc,hh}
 *
 * adapted from comparepackets.{cc,hh}
 */

#include <click/config.h>
#include "comparepairs.hh"
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/standard/scheduleinfo.hh>
CLICK_DECLS

ComparePairs::ComparePairs()
    : _ndiff(0), _task(this)
{
    _p[0] = _p[1] = 0;
    memset(_diff_details, 0, sizeof(_diff_details));
}

ComparePairs::~ComparePairs()
{
}

int
ComparePairs::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool timestamp = true;
    if (cp_va_kparse(conf, this, errh,
		     "TIMESTAMP", 0, cpBool, &timestamp,
		     cpEnd) < 0)
	return -1;
    _timestamp = timestamp;
    return 0;
}

int
ComparePairs::initialize(ErrorHandler *errh)
{
    ScheduleInfo::initialize_task(this, &_task, true, errh);
    return errh->error("this element does not work");
    return 0;
}

void
ComparePairs::cleanup(CleanupStage)
{
    if (_p[0])
	_p[0]->kill();
    if (_p[1])
	_p[1]->kill();
}

void
ComparePairs::check(Packet *p, Packet *q)
{
    bool different = false;

    if (p->length() != q->length())
	_diff_details[D_LEN]++, different = true;
    if (memcmp(p->data(), q->data(), p->length()) != 0)
	_diff_details[D_DATA]++, different = true;
    if (p->timestamp_anno() != q->timestamp_anno() && _timestamp)
	_diff_details[D_TIMESTAMP]++, different = true;

    if (p->has_network_header() && q->has_network_header()) {
	if (p->network_header_offset() != q->network_header_offset())
	    _diff_details[D_NETOFF]++, different = true;
	if (p->network_header_length() != q->network_header_length())
	    _diff_details[D_NETLEN]++, different = true;
    } else if (p->has_network_header() != q->has_network_header())
	_diff_details[D_NETHDR]++, different = true;

    if (different)
	_ndiff++;
}

bool
ComparePairs::run_task(Task*)
{
    assert((_p[0] == NULL) || (_p[1] == NULL));

    click_chatter("run task!");

    if (_p[0] == NULL) {
        _p[0] = input(0).pull();
        if (_p[0] == NULL) {
            click_chatter("nothing in input 0");
            _signal = Notifier::upstream_empty_signal(this, 0, &_task);
            return false;
        }
    }
    assert(_p[0] != NULL);

    if (_p[1] == NULL) {
        _p[1] = input(1).pull();
        if (_p[1] == NULL) {
            click_chatter("nothing in input 1");
            _signal = Notifier::upstream_empty_signal(this, 1, &_task);
            return false;
        }
    }
    assert(_p[1] != NULL);

    click_chatter("checking a pair");

    check(_p[0], _p[1]);
    _p[0]->kill();
    _p[0] = NULL;
    _p[1]->kill();
    _p[0] = NULL;
    return true;
}

enum { H_DIFFS, H_DIFF_DETAILS, H_ALL_SAME };

static const char * const reason_texts[] = {
    "different length", "different data", "different timestamp",
    "different network header offset", "different network header length",
    "different network header presence",
    "more packets in [0]", "more packets in [1]"
};

String
ComparePairs::read_handler(Element *e, void *thunk)
{
    const ComparePairs *cp = static_cast<ComparePairs *>(e);
    switch ((uintptr_t) thunk) {
      case H_DIFFS:
	return String(cp->_ndiff);
      case H_DIFF_DETAILS: {
	  StringAccum sa;
	  for (int i = 0; i < D_LAST; i++)
	      sa << cp->_diff_details[i] << '\t' << reason_texts[i] << '\n';
	  return sa.take_string();
      }
      case H_ALL_SAME:
	return cp_unparse_bool(cp->_ndiff == 0);
      default:
	return "<error>";
    }
}

void
ComparePairs::add_handlers()
{
    add_read_handler("diffs", read_handler, (void *) H_DIFFS);
    add_read_handler("diff_details", read_handler, (void *) H_DIFF_DETAILS);
    add_read_handler("all_same", read_handler, (void *) H_ALL_SAME);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ComparePairs)
