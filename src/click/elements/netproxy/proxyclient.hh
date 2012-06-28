#ifndef CLICK_PROXYCLIENT_HH
#define CLICK_PROXYCLIENT_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/ipaddress.hh>
#include <click/notifier.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include "proxysender.hh"
#include "../buffer.h"
#include "../loghandler.hh"
#include "../quicklz.h"
CLICK_DECLS

/*
=c
ProxyClient()
*/

/*
 * According to the QuickLZ manual, the maximum that a data buffer can expand
 * during compression is 400 bytes.
 * http://www.quicklz.com/manual.html
 */
#define QLZ_MAX_INFLATE 400

class ProxySender;

class ProxyClient {
public:
    ProxyClient(Element *elt);
    ~ProxyClient();

    inline void add_fd(int, ProxySender*);
    inline void add_task(Task*, ProxySender*);
    inline void add_timer(Timer*, ProxySender*);
    void close();
    bool close(const IPAddress*);
    bool create_connection(const struct sockaddr_in*, const struct sockaddr_in*);
    void get_connections(Vector<ProxySender*> *vec);
    virtual Packet *get_input(const struct sockaddr_in*) = 0;
    virtual NotifierSignal *get_signal(const struct sockaddr_in*, Task *) = 0;
    virtual void reject_packet(const struct sockaddr_in*, Packet *);
    inline void remove_fd(int);
    inline void remove_task(Task*);
    inline void remove_timer(Timer*);
    inline bool run_task(Task*);
    inline void run_timer(Timer*);
    inline bool selected(int);
    inline void set_bufsize(size_t size) { _outbufsz = size; }
    inline void set_logger(Logger *log);
    void trace_performance(bool yes);

protected:
    Element *_elt;
    Logger *_log;

private:
    size_t _outbufsz;
    HashMap<IPAddress, ProxySender*> _senders;
    HashMap<int, ProxySender*> _fd_hash;
    HashMap<Task*, ProxySender*> _task_hash;
    HashMap<Timer*, ProxySender*> _timer_hash;
    bool _trace_perf;
};

void
ProxyClient::add_fd(int fd, ProxySender *sender)
{
    bool is_new = _fd_hash.insert(fd, sender);
    if (!is_new)
        _log->error("ProxyClient::add_fd() called for existing fd %d", fd);
}

void
ProxyClient::add_task(Task *task, ProxySender *sender)
{
    bool is_new = _task_hash.insert(task, sender);
    if (!is_new)
        _log->error("ProxyClient::add_task() called for existing task");
}

void
ProxyClient::add_timer(Timer *timer, ProxySender *sender)
{
    bool is_new = _timer_hash.insert(timer, sender);
    if (!is_new)
        _log->error("ProxyClient::add_timer() called for existing timer");
}

void
ProxyClient::remove_fd(int fd)
{
    bool found = _fd_hash.erase(fd);
    if (!found)
        _log->error("ProxyClient::remove_fd() called for unknown fd %d", fd);
}

void
ProxyClient::remove_task(Task *task)
{
    bool found = _task_hash.erase(task);
    if (!found)
        _log->error("ProxyClient::remove_task() called for unknown task");
}

void
ProxyClient::remove_timer(Timer *timer)
{
    bool found = _timer_hash.erase(timer);
    if (!found)
        _log->error("ProxyClient::remove_timer() called for unknown timer");
}

bool
ProxyClient::run_task(Task *task)
{
    ProxySender *sender = _task_hash.find(task);
    if (sender == NULL) {
        _log->warning("ProxyClient::run_task() called for unknown task");
        return false;
    }

    return sender->run_task(task);
}

void
ProxyClient::run_timer(Timer *timer)
{
    ProxySender *sender = _timer_hash.find(timer);
    if (sender == NULL) {
        _log->warning("ProxyClient::run_timer() called for unknown timer");
        return;
    }

    sender->run_timer(timer);
}

bool
ProxyClient::selected(int fd)
{
    ProxySender *sender = _fd_hash.find(fd);
    if (sender == NULL) return false;

    sender->selected(fd);
    return true;
}

void
ProxyClient::set_logger(Logger *l)
{
    _log = l->clone("[ProxyClient] ");
}

CLICK_ENDDECLS
#endif
