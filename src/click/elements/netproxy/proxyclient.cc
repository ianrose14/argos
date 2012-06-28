/*
 * proxyclient.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "proxyclient.hh"
#include <click/confparse.hh>
#include <click/element.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
CLICK_DECLS

ProxyClient::ProxyClient(Element *elt)
    : _elt(elt), _outbufsz(256*1024), _trace_perf(false)
{
}

ProxyClient::~ProxyClient()
{
    close();
}

void
ProxyClient::close()
{
    HashMap<IPAddress, ProxySender*>::iterator iter = _senders.begin();
    for (; iter != _senders.end(); iter++) {
        ProxySender *sender = iter.value();
        sender->close();
        delete sender;
    }

    _senders.clear();
}

bool
ProxyClient::close(const IPAddress *addr)
{
    ProxySender *sender = _senders.find(*addr);
    if (sender == NULL) return false;

    // don't bother log anything because ProxySender::close() will do that
    sender->close();
    delete sender;
    bool deleted = _senders.erase(*addr);
    assert(deleted == true);
    return true;
}

bool
ProxyClient::create_connection(const struct sockaddr_in *remote,
    const struct sockaddr_in *local)
{
    ProxySender *sender = new ProxySender(remote, local, _outbufsz, _elt, this);
    sender->set_logger(_log);  // set log *before* initialize!
    sender->initialize();
    _senders.insert(IPAddress(remote->sin_addr), sender);
    return true;
}

void
ProxyClient::get_connections(Vector<ProxySender*> *vec)
{
    HashMap<IPAddress, ProxySender*>::iterator iter = _senders.begin();
    for (; iter != _senders.end(); iter++) {
        vec->push_back(iter.value());
    }
}

void
ProxyClient::reject_packet(const struct sockaddr_in*, Packet *p)
{
    // default implementation: just kill it
    p->kill();
}

void
ProxyClient::trace_performance(bool yes)
{
    _trace_perf = yes;
    
    HashMap<int, ProxySender*>::iterator iter = _fd_hash.begin();
    for (; iter != _fd_hash.end(); iter++)
        iter.value()->trace_performance(yes);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(proxysender)
ELEMENT_PROVIDES(proxyclient)
