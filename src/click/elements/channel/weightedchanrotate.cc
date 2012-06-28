/*
 * weightedchanrotate.{cc,hh} -- implements a weighted-duration channel rotation policy
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "weightedchanrotate.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include "wifichannel.hh"
#include "../argos/anno.h"
CLICK_DECLS


WeightedChanRotate::WeightedChanRotate()
    : _active(true), _timer(this), _period(MAX_80211_CHANNEL*100), _min_interval(100)
{
}

WeightedChanRotate::~WeightedChanRotate()
{
}

enum { H_ACTIVE };

void
WeightedChanRotate::add_handlers()
{
    add_data_handlers("active", Handler::OP_READ, &_active);
    add_write_handler("active", write_handler, (void *)H_ACTIVE);
}

int
WeightedChanRotate::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "HANDLER", cpkM, cpString, &_setchan_handler_name,
            "PRIORITY", 0, cpInteger, &_priority,
            "PERIOD", 0, cpSecondsAsMilli, &_period,
            "MIN_INTERVAL", 0, cpSecondsAsMilli, &_min_interval,
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

    if ((_min_interval*MAX_80211_CHANNEL) > _period)
        return errh->error("MIN_INTERVAL too big (or PERIOD too small)");

    if (_min_interval == 0)
        return errh->error("MIN_INTERVAL must be > 0");

    _log->debug("period: %u ms", _period);
    _log->debug("min-interval: %u ms", _min_interval);

    // all intervals are equal for the first period
    uint32_t interval = _period / MAX_80211_CHANNEL;
    _log->debug("initial interval: %u ms", interval);

    for (int i=0; i < MAX_80211_CHANNEL; i++) {
        _counts.push_back(0);
        _intervals.push_back(interval);
        _dwell_times.push_back(interval);
    }

    return 0;
}

int
WeightedChanRotate::initialize(ErrorHandler *errh)
{
    _timer.initialize(this);

    if (!cp_handler(_setchan_handler_name, Handler::OP_WRITE, &_setchan_element,
            &_setchan_handler, this, errh))
        return -EINVAL;

    // this will trigger a channel change to channel 1
    _current_channel = 0;
    _chan_start = Timestamp::now();
    _timer.schedule_now();

    return 0;
}

void
WeightedChanRotate::run_timer(Timer *)
{
    if (_current_channel > 0) {
        Timestamp now = Timestamp::now();
        _dwell_times[_current_channel-1] = (now - _chan_start).msecval();
    }

    if (_current_channel == MAX_80211_CHANNEL) {
        // the period has ended, time to calculate new shares for the next
        // period

        double total_rates = 0;  // sum of each channel's packet rate
        Vector<double> capt_rates;
        for (int i=0; i < _counts.size(); i++) {
            // under rare circumstances (such a very long channel change) the
            // dwell time comes out as 0 which makes for a divide by 0; instead
            // we just assign the channel a rate of 0 and trust that it will
            // sort itself out next period (in which it will be given a
            // min-interval sized share)
            double rate;
            if (_dwell_times[i] == 0)
                rate = 0;
            else
                rate = _counts[i] / (double)_dwell_times[i];

            capt_rates.push_back(rate);
            total_rates += rate;
        }

        // before clearing the intervals, check the total_rates; if the
        // total_rates is 0 (usually meaning no packets were captured at all
        // during the entire last period) then we just re-use the same intervals
        // as last time
        if (total_rates > 0) {
            for (int i=0; i < _intervals.size(); i++)
                _intervals[i] = 0;

            uint32_t time_left = _period;
            double rates_sum_left = total_rates;

            while (1) {
                // across all channels still unassigned, find the one with the
                // minimum packet rate
                double min_pkt_rate = 0;
                int min_index = -1;
                for (int i=0; i < _intervals.size(); i++) {
                    if (_intervals[i] != 0)
                        continue;

                    if ((min_index == -1) || (capt_rates[i] < min_pkt_rate)) {
                        min_pkt_rate = capt_rates[i];
                        min_index = i;
                    }
                }

                if (min_index == -1) break;  // done!

                assert(rates_sum_left > 0);
                double share = min_pkt_rate / rates_sum_left;
                double ival = share*time_left;

                if (ival < _min_interval)
                    _intervals[min_index] = _min_interval;
                else
                    _intervals[min_index] = (uint32_t)ival;

                total_rates -= min_pkt_rate;
                assert(total_rates >= -0.00001);  // allow floating point slack

                assert(time_left >= _intervals[min_index]);
                time_left -= _intervals[min_index];

                rates_sum_left -= capt_rates[min_index];
            }

            assert(total_rates <= 0.00001);  // allow floating point slack
            assert(time_left < 12);  // allow rounding slack
        }
 
        StringAccum sa;
        uint32_t t;

        t = 0;
        sa << "counts:";
        for (int i=0; i < _counts.size(); i++) {
            sa << "  " << i+1 << "=" << _counts[i];
            t += _counts[i];
        }
        sa << "  (total: " << t << ")";
        _log->debug(sa.take_string().c_str());

        t = 0;
        sa << "dwell-times (ms):";
        for (int i=0; i < _dwell_times.size(); i++) {
            sa << "  " << i+1 << "=" << _dwell_times[i];
            t += _dwell_times[i];
        }
        sa << "  (total: " << t << ")";
        _log->debug(sa.take_string().c_str());

        t = 0;
        sa << "rates:";
        for (int i=0; i < capt_rates.size(); i++) {
            sa << "  " << i+1 << "=" << capt_rates[i];
            t += _counts[i];
        }
        _log->debug(sa.take_string().c_str());

        t = 0;
        sa << "new intervals (ms):";
        for (int i=0; i < _intervals.size(); i++) {
            sa << "  " << i+1 << "=" << _intervals[i];
            t += _intervals[i];
        }
        sa << "  (total: " << t << ")";
        _log->debug(sa.take_string().c_str());

        _current_channel = 0;

        // reset counts to 0 for the new period
        for (int i=0; i < _counts.size(); i++)
            _counts[i] = 0;
    }

    _current_channel++;

    Timestamp interval = Timestamp::make_msec(_intervals[_current_channel-1]);
    _timer.schedule_after(interval);

    // args: <NAME> <PRIORITY> <CHANNEL> <DURATION>
    StringAccum sa;
    sa << name().c_str() << " " << _priority << " " << (int)_current_channel
       << " " << interval;

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _setchan_handler->call_write(sa.take_string(), _setchan_element, &errh);
    if (rv >= 0) {
        _log->debug("setchan handler (%hhu) success for %s sec", _current_channel,
            interval.unparse().c_str());
    } else {
        if (rv == -EPERM)
            _log->debug("setchan handler (%hhu) failed: %s", _current_channel,
                errh.get_last_error().c_str());
        else
            _log->error("setchan handler (%hhu) failed: %s", _current_channel,
                errh.get_last_error().c_str());
    }

    _chan_start = Timestamp::now();
}

/* Protected Methods */

bool
WeightedChanRotate::get_active()
{
    return _active;
}

String
WeightedChanRotate::read_handler(Element *e, void *thunk)
{
    WeightedChanRotate *elt = dynamic_cast<WeightedChanRotate*>(e);
    int which = reinterpret_cast<int>(thunk);

    switch (which) {
    case H_ACTIVE:
        return String(elt->get_active());
    default:
        return "<invalid handler>";
    }
}

void
WeightedChanRotate::set_active(bool yes)
{
    _active = yes;
}

Packet *
WeightedChanRotate::simple_action(Packet *p)
{
    const uint8_t *anno_ptr = p->anno_u8() + ARGOS_SNIFF_ANNO_OFFSET;
    struct argos_sniff *sniff = (struct argos_sniff *)anno_ptr;

    if (sniff->magic != ARGOS_SNIFF_MAGIC)
        return p;  // no sniffer annotation - ignore packet

    // we haven't set the channel at all yet, so we don't know what channel we
    // are tuned to
    if (_current_channel == 0)
        return p;

    // note - add a little slack time because packets might be received a little
    // before we managed to set _chan_start's value
    if (p->timestamp_anno() >= (_chan_start - Timestamp::make_msec(5))) {
        // looks like packet was captured while tuned to the current channel

        // the current channel only gets "credit" for a packet capture if the
        // packet's transmission channel is unknown (0) or matches the channel
        // that we are tuned to
        if ((sniff->channel == 0) || (sniff->channel == _current_channel)) {
            _counts[_current_channel-1]++;
        }
    } else {
        // assume packet was captured while tuned to the previous channel

        if (_current_channel == 1)
            // oops.. this packet appears to have been captured during our last
            // iteration through the channels - its too late to do anything with
            // it now...
            return p;

        uint8_t prev_channel = _current_channel - 1;

        // the current channel only gets "credit" for a packet capture if the
        // packet's transmission channel is unknown (0) or matches the channel
        // that we were previously tuned to
        if ((sniff->channel == 0) || (sniff->channel == prev_channel)) {
            _counts[prev_channel-1]++;
        }
    }

    return p;
}

int
WeightedChanRotate::write_handler(const String &s_in, Element *e, void *thunk,
    ErrorHandler *errh)
{
    WeightedChanRotate *elt = dynamic_cast<WeightedChanRotate*>(e);
    int which = reinterpret_cast<int>(thunk);
    String s = cp_uncomment(s_in);

    switch (which) {
    case H_ACTIVE: {
        bool active;
        if (cp_bool(s, &active)) {
            elt->set_active(active);
            return 0;
        } else {
            return errh->error("'active' should be Boolean");
        }
    }
    default:
        return errh->error("unknown handler");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(WeightedChanRotate)
