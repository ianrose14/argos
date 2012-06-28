#ifndef CLICK_LOGHANDLER_HH
#define CLICK_LOGHANDLER_HH
#include <click/element.hh>
#include <click/error.hh>
#include <click/task.hh>
#include <click/standard/scheduleinfo.hh>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
CLICK_DECLS

/*
 * Convenience Method
 */
void simple_log_error(const Element *, const char *, ...);

enum LogLevel {
    LOG_DEBUG=0,
    LOG_DATA,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_CRITICAL,
    LOG_NOTHING,     // used for a Log object that should print nothing
    LOG_INVALID=999  // used only as a return value from Log::parse_level()
};

class Logger;

/*
 * LogHandler class
 */
class LogHandler : public Element {
public:
    LogHandler();
    ~LogHandler();

    const char *class_name() const	{ return "LogHandler"; }
    int configure_phase() const		{ return CONFIGURE_PHASE_INFO; }
    const char *port_count() const	{ return "0-1/0-1"; }
    const char *processing() const	{ return PUSH; }
    const char *flow_code() const       { return "x/y"; }

    void add_handlers();
    void *cast(const char *);
    void cleanup(CleanupStage);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void push(int, Packet*);
    bool run_task(Task *);

    static Logger *get_logger(const Element *, const char *, const char*,
        const char*, const char*, ErrorHandler*);

    static void chatter_log(const Timestamp &ts, const String &source, LogLevel lvl,
        const String &msg);

    int log_handler(const Timestamp &ts, const String &source, LogLevel lvl,
        const String &msg, ErrorHandler *errh);

    int net_log(const Timestamp &ts, const String &source, LogLevel lvl,
        const String &msg);

private:
    static int make_header(String &source, enum LogLevel lvl, String &out);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    Task _task;
    bool _ok_to_push;
    enum LogLevel _def_local_thresh, _def_net_thresh;
};

/*
 * Logger class
 */
class Logger {
public:
    Logger(const String &source, const String &prefix, enum LogLevel local_thresh,
        enum LogLevel net_thresh, LogHandler *handler);
    ~Logger() {}

    inline const String &source() const { return _source; }
    inline const String &prefix() const { return _prefix; }
    inline const LogLevel local_thresh() const { return _local_thresh; }
    inline const LogLevel net_thresh() const { return _net_thresh; }
    inline LogHandler *handler() { return _handler; }

    Logger *clone(const char *prefix);

    // convenience logging methods
    void debug(const char *fmt, ...);
    void data(const char *fmt, ...);
    void info(const char *fmt, ...);
    void warn(const char *fmt, ...);
    void warning(const char *fmt, ...);
    void err(const char *fmt, ...);
    void error(const char *fmt, ...);
    void crit(const char *fmt, ...);
    void critical(const char *fmt, ...);
    void strerror(const char *fmt, ...);

    // accessory methods
    static enum LogLevel parse_level(const char*, enum LogLevel def);

    static const char *level_descs[];

private:
    void log(LogLevel lvl, const char *fmt, va_list ap, int errnum=0);

    String _source, _prefix, _net_prefix;
    enum LogLevel _local_thresh, _net_thresh;
    LogHandler *_handler;
};

#define LOGHANDLER_NETLOG_MAGIC 0x195F

struct loghandler_netlog_header {
    uint16_t magicnum;
    uint8_t loglevel;
    uint8_t unused_space;
    // no need for a timestamp field because packets have one built-in
    char source[28];
} CLICK_SIZE_PACKED_ATTRIBUTE;

/*
 * StoredErrorHandler class
 */
class StoredErrorHandler : public ErrorHandler {
public:
    StoredErrorHandler() : _has_error(false) {}

    void *emit(const String &str, void *user_data, bool more);
    String &get_last_error() { _has_error = false; return _last_error; }
    bool has_error() { return _has_error; }

private:
    String _last_error;
    bool _has_error;
};


CLICK_ENDDECLS
#endif
