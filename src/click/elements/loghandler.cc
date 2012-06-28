/*
 * loghandler.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "loghandler.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <unistd.h>
CLICK_DECLS

void simple_log_error(const Element *elt, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    char *msg = NULL;
    vasprintf(&msg, fmt, ap);

    StoredErrorHandler errh;
    Logger *l = LogHandler::get_logger(elt, NULL, "ERROR", "ERROR", NULL, &errh);

    if (l == NULL) {
        click_chatter("get_logger: %s", errh.get_last_error().c_str());

        if (msg == NULL)
            click_chatter("vasprintf: %s", strerror(errno));
        else
            click_chatter("%s: %s", elt->name().c_str(), msg);
    } else {
        if (msg == NULL)
            l->error("vasprintf: %s", strerror(errno));
        else
            l->error("%s", msg);
    }

    free(msg);
    va_end(ap);
}


/*
 * LogHandler Methods
 */
LogHandler::LogHandler()
    : _task(this), _ok_to_push(false)
{
}

LogHandler::~LogHandler()
{
}

enum { H_LOG };

void
LogHandler::add_handlers()
{
    add_write_handler("log", write_handler, (void*)H_LOG);
}

void *
LogHandler::cast(const char *n)
{
    if (strcmp(n, "LogHandler") == 0)
        return (LogHandler *)this;
    else
        return 0;
}

void
LogHandler::cleanup(CleanupStage)
{
    // many elements spit out log messages during the shutdown process, such as
    // in cleanup() or their destructor - this can be bad if the log message is
    // supposed to be net-logged, because the LogHandler element will create a
    // packet for the log message and push it to the next element.  But if Click
    // is tearing down the click configuration, that next element may no longer
    // exist!  So once cleanup() is called on a LogHandler, it will refuse to
    // push any more packets.
    _ok_to_push = false;
}

int
LogHandler::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // the (default) default thresholds are INFO for local logging and DATA for
    // network logging
    String loglevel = "INFO", netlog = "DATA";

    if (cp_va_kparse(conf, this, errh,
            "LOGGING", 0, cpString, &loglevel,
            "NETLOG", 0, cpString, &netlog,
            cpEnd) < 0)
        return -1;

    _def_local_thresh = Logger::parse_level(loglevel.c_str(), LOG_INVALID);
    if (_def_local_thresh == LOG_INVALID)
        return errh->error("invalid loglevel: %s", loglevel.c_str());

    _def_net_thresh = Logger::parse_level(netlog.c_str(), LOG_INVALID);
    if (_def_net_thresh == LOG_INVALID)
        return errh->error("invalid loglevel: %s", netlog.c_str());

    return 0;
}

int
LogHandler::initialize(ErrorHandler *)
{
    ScheduleInfo::initialize_task(this, &_task, true,
        ErrorHandler::default_handler());

    return 0;
}

void
LogHandler::push(int, Packet *p)
{
    size_t hdrlen = sizeof(struct loghandler_netlog_header);

    if (p->length() < hdrlen) {
        click_chatter("%s: invalid packet received (too short: %d)", name().c_str(),
            p->length());
        p->kill();
        return;
    }
    
    struct loghandler_netlog_header *hdr = (struct loghandler_netlog_header*)p->data();

    if (ntohs(hdr->magicnum) != LOGHANDLER_NETLOG_MAGIC) {
        click_chatter("%s: invalid packet received (bad magic number)", name().c_str());
        p->kill();
        return;
    }

    LogLevel lvl = (LogLevel)hdr->loglevel;

    p->pull(hdrlen);
    char *msg = (char*)p->data();

    // note that we do NOT check that (lvl >= _def_local_thresh) because we
    // assume that the remote Logger already applied its own thresholds (which
    // the log message must have passed or it wouldn't have been sent)
    chatter_log(p->timestamp_anno(), String(hdr->source), lvl, String(msg));
    p->kill();
}

bool
LogHandler::run_task(Task*)
{
    // the purpose of this task is to detect when the entire router has been
    // initialized and thus it is save to output packets - elements frequently
    // log things during their configure() and initialize() methods but it is
    // not safe at these times for LogHandler to emit packets to other elements
    _ok_to_push = true;
    return false;  // did not do any real work
}

int
LogHandler::write_handler(const String &s_in, Element *e, void *thunk, ErrorHandler *errh)
{
    LogHandler *elt = static_cast<LogHandler *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    String source = "[handler]", message, loglevel = "INFO";

    Vector<String> conf;
    cp_spacevec(s_in, conf);

    if (cp_va_kparse(conf, NULL, errh,
            "SOURCE", cpkM+cpkP, cpString, &source,
            "LOGGING", cpkM+cpkP, cpString, &loglevel,
            "MESSAGE", cpkM+cpkP, cpString, &message,
            cpEnd) < 0) {

        StringAccum sa;
        sa << "arguments (" << conf.size() << "): ";
        for (int i=0; i < conf.size(); i++)
            sa << "|" << conf[i] << "|, ";

        errh->error(sa.take_string().c_str());
        return -1;
    }

    message = cp_unquote(message);

    LogLevel lvl = Logger::parse_level(loglevel.c_str(), elt->_def_local_thresh);
    if (lvl == LOG_INVALID)
        return errh->error("invalid LOGGING value: %s", loglevel.c_str());

    Timestamp now = Timestamp::now();

    switch (which) {
    case H_LOG:
        return elt->log_handler(now, source, lvl, message, errh);
    default:
        return errh->error("internal error (bad thunk value)");
    }
    
    return 0;
}

Logger *
LogHandler::get_logger(const Element *source, const char *prefix,
    const char *local_thresh, const char *net_thresh, const char *handler_name,
    ErrorHandler *errh)
{
    LogHandler *h = NULL;
    enum LogLevel def_local_thresh = LOG_INFO, def_net_thresh = LOG_DATA;

    if (handler_name != NULL) {
        Element *elt = cp_element(handler_name, source, NULL);
        if (elt != NULL) {
            h = (LogHandler*)elt->cast("LogHandler");
            if (h == NULL) {
                errh->error("named element (%s) is not a LogHandler", elt->name().c_str());
                return NULL;
            }
            def_local_thresh = h->_def_local_thresh;
            def_net_thresh = h->_def_net_thresh;
        }
    }
    // else, there is no handler by that name -- this is ok, it just means that
    // network logging won't happen

    LogLevel local_lvl = Logger::parse_level(local_thresh, def_local_thresh);
    if (local_lvl == LOG_INVALID) {
        errh->error("invalid loglevel: %s", local_thresh);
        return NULL;
    }

    LogLevel net_lvl = Logger::parse_level(net_thresh, def_net_thresh);
    if (net_lvl == LOG_INVALID) {
        errh->error("invalid loglevel: %s", net_thresh);
        return NULL;
    }

    String p = (prefix == NULL) ? String::make_empty() : String(prefix);

    Logger *logger = new Logger(source->name(), p, local_lvl, net_lvl, h);
    if (logger == NULL) {
        errh->error("'new' operator failed to create Logger object");
        return NULL;
    }

    return logger;
}

/* static class method */
void
LogHandler::chatter_log(const Timestamp &ts, const String &source, LogLevel lvl,
    const String &msg)
{
    // format copied from src/orion/log.c

    /*
     * format of string written by ctime_r (all fields fixed width):
     *   Thu Nov 24 18:22:48 1986\n\0
     * the length (26) should be a macro in time.h :(
     */
    uint32_t sec = (uint32_t)ts.sec();
    uint32_t msec = ts.msec();

    time_t t = sec;

    char datebuf[26];
    ctime_r(&t, datebuf);
    datebuf[19] = '\0';  /* truncate off the " 1986\n" at the end */
    char *dateptr = datebuf + 4;  /* skip the "Thu " at the front */
    
    /* args: date-desc, time-milliseconds, source, log-level-desc, message */
    const char *fmt = "%s.%03d %-15s %-5s %s";

    char *line;
    if (asprintf(&line, fmt, dateptr, msec, source.c_str(),
            Logger::level_descs[lvl], msg.c_str()) == -1) {
        click_chatter("LogHandler: asprintf failed");
        return;
    }

    click_chatter("%s", line);
    free(line);
}

int
LogHandler::log_handler(const Timestamp &ts, const String &source, LogLevel lvl,
    const String &msg, ErrorHandler *errh)
{
    if (lvl >= _def_local_thresh)
        chatter_log(ts, source, lvl, msg);

    if (lvl >= _def_net_thresh) {
        if (net_log(ts, source, lvl, msg) == -1)
            return errh->error("net-log failed: %s", strerror(errno));
    }

    return 0;
}

int
LogHandler::net_log(const Timestamp &ts, const String &source, LogLevel lvl,
    const String &msg)
{
    if (!_ok_to_push)
        return -1;

    if (noutputs() == 0)
        return 0;

    size_t msglen = msg.length() + 1;  // include null terminator!
    size_t hdrlen = sizeof(struct loghandler_netlog_header);

    WritablePacket *p;
    try {
        p = Packet::make(hdrlen, msg.c_str(), msglen, 0);
    }
    catch (std::bad_alloc &ex) {
        errno = ENOMEM;
        return -1;
    }

    p->data()[msglen-1] = '\0';
    p->set_timestamp_anno(ts);

    // Packet::push() should always succeed because we acounted for this space
    // when we originally called Packet::make() to create p
    WritablePacket *q = p->push(hdrlen);

    struct loghandler_netlog_header *hdr = (struct loghandler_netlog_header*)q->data();
    hdr->magicnum = htons(LOGHANDLER_NETLOG_MAGIC);
    hdr->loglevel = lvl;
    strlcpy(hdr->source, source.c_str(), sizeof(hdr->source));

    checked_output_push(0, q);
    return 0;
}

/*
 * Logger Methods
 */
const char *Logger::level_descs[] = {
    "DEBUG", "DATA", "INFO", "WARN", "ERR", "CRIT"
};

Logger::Logger(const String &source, const String &prefix, enum LogLevel local_thresh,
    enum LogLevel net_thresh, LogHandler *handler)
    : _source(source), _prefix(prefix), _local_thresh(local_thresh),
      _net_thresh(net_thresh), _handler(handler)
{
    char cbuf[1024];
    if (gethostname(cbuf, sizeof(cbuf)) != 0)
        snprintf(cbuf, sizeof(cbuf), "err_%d", errno);
    _net_prefix = "[net-src: " + String(cbuf) + "] ";
}

Logger *
Logger::clone(const char *prefix)
{
    return new Logger(_source, prefix ? prefix : _prefix, _local_thresh,
        _net_thresh, _handler);
}

void
Logger::debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_DEBUG, fmt, ap);
    va_end(ap);
}

void
Logger::data(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_DATA, fmt, ap);
    va_end(ap);
}

void
Logger::info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_INFO, fmt, ap);
    va_end(ap);
}

void
Logger::warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_WARNING, fmt, ap);
    va_end(ap);
}

void
Logger::warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_WARNING, fmt, ap);
    va_end(ap);
}

void
Logger::err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_ERROR, fmt, ap);
    va_end(ap);
}

void
Logger::error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_ERROR, fmt, ap);
    va_end(ap);
}

void
Logger::crit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_CRITICAL, fmt, ap);
    va_end(ap);
}

void
Logger::critical(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log(LOG_CRITICAL, fmt, ap);
    va_end(ap);
}

void
Logger::strerror(const char *fmt, ...)
{
    int _errno = errno;
    va_list ap;
    va_start(ap, fmt);
    log(LOG_ERROR, fmt, ap, _errno);
    va_end(ap);
}

/* static class method */
enum LogLevel
Logger::parse_level(const char *desc, enum LogLevel def)
{
    // empty string -> use default
    if (strlen(desc) == 0) return def;

    if (strcasecmp(desc, "debug") == 0) return LOG_DEBUG;
    if (strcasecmp(desc, "data") == 0) return LOG_DATA;
    if (strcasecmp(desc, "info") == 0) return LOG_INFO;
    if (strcasecmp(desc, "warning") == 0) return LOG_WARNING;
    if (strcasecmp(desc, "error") == 0) return LOG_ERROR;
    if (strcasecmp(desc, "critical") == 0) return LOG_CRITICAL;
    if (strcasecmp(desc, "nothing") == 0) return LOG_NOTHING;
    return LOG_INVALID;  // error
}

void
Logger::log(LogLevel lvl, const char *fmt, va_list ap, int errnum)
{
    Timestamp now = Timestamp::now();
    char cbuf[4096];

    int len = vsnprintf(cbuf, sizeof(cbuf), fmt, ap);
    if (errnum > 0)
        len += snprintf(cbuf + len, sizeof(cbuf) - len, ": %s", ::strerror(errnum));

    String body = _prefix + String(cbuf);

    // log locally (stdout) if possible
    if (lvl >= _local_thresh)
        LogHandler::chatter_log(now, _source, lvl, body);

    // net-logging is only possible if we have a LogHandler
    if (_handler != NULL) {
        // log via network if possible
        if (lvl >= _net_thresh)
            (void) _handler->net_log(now, _source, lvl, _net_prefix + body);
    }
}


/*
 * StoredErrorHandler Methods
 */
void*
StoredErrorHandler::emit(const String &str, void*, bool)
{
    _last_error = str;
    _has_error = true;
    return 0;  // copied from FileErrorHandler
}

CLICK_ENDDECLS
EXPORT_ELEMENT(LogHandler)
