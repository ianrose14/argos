/*
 * proxysender.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */
#include <click/config.h>
#include "proxysender.hh"
#include <click/element.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "proxyclient.hh"
#include "../argos/net_proto.h"
CLICK_DECLS

#define COMPRESS_MIN_LEN (5*1024)

ProxySender::ProxySender(const struct sockaddr_in *remote, const struct sockaddr_in *local,
    size_t bufsize, Element *elt, ProxyClient *client)
    :  _compress_timer(elt), _connect_timer(elt), _task(elt)
{
    _sock = -1;
    _remote_addr = *remote;
    _has_local_addr = (local != NULL);
    if (_has_local_addr) _local_addr = *local;
    _elt = elt;
    _selecting = false;
    _client = client;

    _cur_backoff = 5;
    _init_backoff = 5;
    _max_backoff = 60;
    _signal = NULL;
    _send_delay = Timestamp::make_msec(100);
    _next_packet = NULL;
    _databuf = buffer_create(bufsize);
    // allocate a little extra space for compression overhead
    _sendbuf = buffer_create(bufsize + 5*1024);

    _bytes_sent = 0;
    _pkts_sent = 0;
    _pkts_buffered = 0;

    _suppress_connect_errors = false;
    _trace_perf = false;
    _log = NULL;
}

ProxySender::~ProxySender()
{
    close();
    buffer_destroy(_databuf);
    buffer_destroy(_sendbuf);
    if (_signal != NULL) delete _signal;
}

int
ProxySender::close()
{
    if (_state == STATE_DEAD) return 0;

    const char *status_desc;
    if ((_state == STATE_IDLE) || (_state == STATE_CONNECTING))
        status_desc = "unconnected";
    else if ((_state == STATE_CONNECTED) || (_state == STATE_BACKOFF))
        status_desc = "connected";
    else
        status_desc = "(unknown)";

    _log->info("closing %s ProxySender to %s", status_desc,
        peer().unparse().c_str());

    if (_sock != -1) {
        remove_select();
        if (_client) _client->remove_fd(_sock);

        if (_sock != -1) {
            do {
                if (::close(_sock) == -1) {
                    if (errno == EINTR)
                        continue;
                    else
                        _log->error("close: %s", strerror(errno));
                }
            } while (0);
        }

        _sock = -1;
    }

    _task.unschedule();
    _compress_timer.unschedule();
    _connect_timer.unschedule();

    if (_client) {
        _client->remove_task(&_task);
        _client->remove_timer(&_compress_timer);
        _client->remove_timer(&_connect_timer);
    }

    _state = STATE_DEAD;
    return 0;
}

int
ProxySender::initialize()
{
    _state = STATE_IDLE;

    if (_client) {
        _client->add_task(&_task, this);
        _client->add_timer(&_compress_timer, this);
        _client->add_timer(&_connect_timer, this);
    }

    _compress_timer.initialize(_elt);
    _connect_timer.initialize(_elt);
    _connect_timer.schedule_now();

    ScheduleInfo::initialize_task(_elt, &_task, true,
        ErrorHandler::default_handler());

    _signal = _client->get_signal(&_remote_addr, &_task);
    return 0;
}

bool
ProxySender::run_task(Task *)
{
    // the task runs when the signal tells us that there is data available to
    // "pull"
    uint32_t space = buffer_remaining(_databuf);

    if (_next_packet == NULL)
        _next_packet = _client->get_input(&_remote_addr);

    if (_next_packet != NULL) {
        size_t reqlen = get_serialized_len(_next_packet);

        if (reqlen > space) {
            // not enough space in the databuf to serialize this packet -
            // confirm that we will eventually have enough room (once the
            // databuf is totally empty)
            if (reqlen > buffer_size(_databuf)) {
                _log->warning("packet too big for databuf (%d bytes)", reqlen);
                _client->reject_packet(&_remote_addr, _next_packet);
                _next_packet = NULL;
                _task.fast_reschedule();
                return true;
            } else {
                // there will be enough room once databuf drains; do not
                // reschedule task and "bump up" the compression timer to fire
                // right now (since there is no point in waiting for more input
                // if we know now that none will come)
                assert(buffer_len(_databuf) > 0);
                _compress_timer.schedule_now();
                return true;
            }
        } else {
            // pull succeeded (or a packet was waiting in _next_packet)
            size_t written = serialize_packet(_next_packet,
                buffer_tail(_databuf), space);
            assert(written == reqlen);
            int rv = buffer_expand(_databuf, written);
            assert(rv == 0);

            _pkts_buffered++;

            // if compression timer is not scheduled, schedule it
            if (!_compress_timer.scheduled())
                _compress_timer.schedule_after(_send_delay);

            _next_packet->kill();
            _next_packet = NULL;

            // reschedule to see if there is more than we can pull
            _task.fast_reschedule();
            return true;
        }
    }

    if (_signal->active())
        _task.fast_reschedule();

    return false;  // no packet returned by get_input
}

void
ProxySender::run_timer(Timer *timer)
{
    if (timer == &_compress_timer)
        run_compress_timer();
    else if (timer == &_connect_timer)
        run_connect_timer();
    else {
        _log->error("%s ProxySender::run_timer(): unknown timer");
        close();
    }
}

void
ProxySender::selected(int fd)
{
    assert(fd == _sock);

    if (_state == STATE_CONNECTING)
        handle_connect();
    else
        handle_writable();
}

/*
 * Protected Methods
 */


/*
 * Private Methods
 */

void
ProxySender::add_select()
{
    _elt->add_select(_sock, Element::SELECT_WRITE);
    _selecting = true;
}

void
ProxySender::compress_databuf()
{
    size_t len = buffer_len(_databuf);
    assert(len > 0);
    assert(buffer_len(_sendbuf) == 0);

    uint32_t write_len;

    // if there isn't much in the data-buffer, don't bother try to compress it
    // (just copy it directly over)
    if (len < COMPRESS_MIN_LEN) {
        Timestamp start = Timestamp::now();
        memcpy(buffer_tail(_sendbuf), buffer_head(_databuf), len);
        write_len = len;

        if (_trace_perf) {
            Timestamp elapsed = Timestamp::now() - start;
            u_int elapsed_ms = elapsed.msecval();
            double bw = elapsed ? len/(1024*1024*elapsed.doubleval()) : 0;

            _log->debug("memcpy'ed %u bytes (%u packets) in %u ms (%.2f MB/s)",
                len, _pkts_buffered, elapsed_ms, bw);
        }
    } else {
        // where the compressed data should be written
        u_char *write_ptr = buffer_tail(_sendbuf) +
            sizeof(struct argos_net_compress_msg);

        struct argos_net_compress_msg *msg =
            (struct argos_net_compress_msg*)buffer_tail(_sendbuf);
        msg->msgtype = htons(ARGOS_NET_COMPRESS_MSGTYPE);
        // have to defer filling in msglen field
        msg->algorithm = ARGOS_NET_COMPRESS_QUICKLZ;
        msg->orig_len = htonl(len);

        Timestamp start = Timestamp::now();
        uint32_t outlen = qlz_compress(buffer_head(_databuf), (char*)write_ptr, len,
            _qlz_scratch);

        if (_trace_perf) {
            Timestamp elapsed = Timestamp::now() - start;
            u_int elapsed_ms = elapsed.msecval();
            double compress_ratio = (double)outlen*100/len;
            double bw = elapsed ? len/(1024*1024*elapsed.doubleval()) : 0;

            _log->debug("compressed %u bytes (%u packets) to %u (%.2f%%) in %u ms"
                " (%.2f MB/s)", len, _pkts_buffered, outlen, compress_ratio,
                elapsed_ms, bw);
        }

        // write back into the msglen field now that we know the total length
        write_len = sizeof(struct argos_net_compress_msg) + outlen;
        msg->msglen = htonl(write_len);

        // check for incompressible block (this is very common for small blocks,
        // and actually not that rate for [certain?] larger blocks either)
        if ((outlen > len) && (len >= 4096))
            _log->debug("incompressible block: inlen=%d, outlen=%d", len, outlen);
    }

    int rv = buffer_discard(_databuf, len);
    assert(rv == 0);
    rv = buffer_expand(_sendbuf, write_len);
    assert(rv == 0);

    _pkts_compressed = _pkts_buffered;
    _pkts_buffered = 0;

    // now that sendbuf is non-empty, select for writes
    add_select();

    // now that databuf is empty, its ok to pull more data into it
    if (_signal->active())
        _task.reschedule();
}

void
ProxySender::handle_connect()
{
    assert(_state == STATE_CONNECTING);

    // connect() completed, but did it succeed or fail?  getpeername() will
    // tell us.  reference: http://cr.yp.to/docs/connect.html
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    if (getpeername(_sock, (struct sockaddr*)&sin, &slen) == -1) {
        if (errno == ENOTCONN) {
            // connect failed; ok, now use error slippage to get the real error
            char c;
            int rv = read(_sock, &c, 1);
            assert(rv == -1);
            handle_connect_failure();
        } else if (errno == ECONNRESET) {
            // not sure if this can actually happen - perhaps with perfect
            // timing (connection lost right before we call getpeername)
            _log->strerror("getpeername");
            reset_connection();
        } else {
            // this is unexpected...
            _log->strerror("getpeername");
            _log->critical("unexpected getpeername() error after asynchronous"
                " connect() selected for writability; connection is now dead");
            close();
        }
    } else {
        // connect succeeded
        _log->info("connect() succeeded asynchronously to %s:%d",
            inet_ntoa(_remote_addr.sin_addr), ntohs(_remote_addr.sin_port));
        handle_connect_success();
    }
}

void
ProxySender::handle_connect_failure()
{
    switch (errno) {
        /* these errors indicate some kind of programming error */
    case EBADF:
    case ENOTSOCK:
    case EAFNOSUPPORT:
    case EFAULT:
        /* fall through */

        /*
         * generally, these are non-fatal, but should never happen in this
         * code; if they do, this indicates a programming error
         */
    case EISCONN:
    case EALREADY:
        _log->strerror("connect");
        _log->critical("unexpected connect() error; connection is now dead");
        close();
        return;
        
        /* these are transient errors; we retry connecting */
    case EADDRNOTAVAIL:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case EADDRINUSE:
    case ECONNRESET:
        /* fall through */

        /*
         * EAGAIN is NOT the same as EINPROGRESS; it means that the server's
         * connection backlog is full
         */
    case EAGAIN:
        if (!_suppress_connect_errors) {
            _log->warning("connect() failed with transient error: %s",
                strerror(errno));
            _log->info("suppressing further errors for transient connect failures");
            _suppress_connect_errors = true;
        }
        reset_connection();
        return;

        /* these aren't really errors; the connect() should still work */
    case EINPROGRESS:
        /*
         * this errno is ok if returned by connect() itself, but shouldn't be
         * returned via error slippage from a recv() after a failed connect
         */
        if (_state == STATE_CONNECTING) {
            _log->strerror("read after failed connect");
            _log->critical("unexpected recv() error; connection is now dead");
            close();
            return;
        }
        /* fall through */

    case EINTR:
        _log->debug("connect() in progress (\"%s\")", strerror(errno));
        _state = STATE_CONNECTING;
        return;

    case ENETUNREACH:
    case EHOSTUNREACH:
        /*
         * ENETUNREACH happens if there if some node on the routing path
         * (perhaps the localhost) can't get to the specified subnet - this
         * might indicate a routing problem.  I don't know what could cause an
         * EHOSTUNREACH error.
         */
        _log->strerror("connect");
        _log->critical("connect attempt failed; connection is now dead");
        close();
        return;

    default:
        /* unknown errno */
        if (_state == STATE_CONNECTING)
            _log->strerror("read after failed connect");
        else
            _log->strerror("connect");
        _log->critical("unexpected connect errno");
        close();
        return;
    }
}

void
ProxySender::handle_connect_success()
{
    _state = STATE_CONNECTED;
    _suppress_connect_errors = false;

    // if the sendbuf is empty (which is normally is, the exception being if
    // this is a RE-connection in which case there might already be data sitting
    // around waiting to be sent), don't select for writing to the socket
    if (buffer_len(_sendbuf) == 0)
        remove_select();

    /* reset backoff upon successful connects */
    _cur_backoff = _init_backoff;

    /* schedule task (which takes care of pulling input) */
    _task.reschedule();
}

void
ProxySender::handle_writable()
{
    size_t reqlen = buffer_len(_sendbuf);

    if (reqlen == 0) {
        _log->warning("selected() called when sendbuf.len=0");
        return;
    }

    Timestamp start = Timestamp::now();

    ssize_t len = send(_sock, buffer_head(_sendbuf), reqlen, 0);
    if (len == -1) {
        if (errno == EAGAIN) {  // do not treat as an error
            _log->warning("send() failed with EAGAIN");
            return;
        }

        if ((errno == ENOBUFS) || (errno == ECONNREFUSED) || (errno == EPIPE)) {
            // these errors can occur "normally" due to typical, transient
            // errors (such as nodes being temporarily offline)
            _log->warning("send: %s", strerror(errno));
        } else {
            // perhaps a more serious error...
            _log->strerror("send");
        }

        reset_connection();
        return;
    } else {
        // send() succeeded
        assert(len > 0);

        if (_trace_perf) {
            Timestamp elapsed = Timestamp::now() - start;
            u_int elapsed_ms = elapsed.msecval();
            double bw = elapsed ? (len*8)/(1024*1024*elapsed.doubleval()) : 0;
            _log->debug("sent %u bytes in %d ms (%.2f Mbit/s); requested %u",
                len, elapsed_ms, bw, reqlen);
        }

        int rv = buffer_discard(_sendbuf, len);
        assert(rv == 0);
        _bytes_sent += len;

        // if sendbuf is now empty, try to fill it (by compressing data from
        // the databuf)
        if (buffer_len(_sendbuf) == 0) {
            _pkts_sent += _pkts_compressed;
            _pkts_compressed = 0;

            if (buffer_len(_databuf) > 0) {
                // if the compression timer is scheduled, then do NOT touch the
                // databuf (the data is currently in the waiting period after it
                // is was first enqueued)
                if (!_compress_timer.scheduled())
                    // else, ok to compress data from databuf to sendbuf
                    compress_databuf();
            }
        }

        // if sendbuf is STILL empty, stop selecting for writes
        if (buffer_len(_sendbuf) == 0) {
            remove_select();
        }
    }
}

void
ProxySender::remove_select()
{
    _elt->remove_select(_sock, Element::SELECT_WRITE);
    _selecting = false;
}

void
ProxySender::reset_connection()
{
    _state = STATE_BACKOFF;
    _connect_timer.reschedule_after_sec(_cur_backoff);

    remove_select();
    if (_client) _client->remove_fd(_sock);

    do {
        if (::close(_sock) == -1) {
            if (errno == EINTR)
                continue;
            else
                _log->error("close: %s", strerror(errno));
        }
    } while (0);

    _sock = -1;

    /* exponentially increase backoff */
    _cur_backoff *= 2;
    if (_cur_backoff > _max_backoff)
        _cur_backoff = _max_backoff;
}

void
ProxySender::run_compress_timer()
{
    // the timer fires when its time to compress data from the databuf and
    // tranfer it to the sendbuf
    if (buffer_len(_databuf) == 0) {
        _log->warning("timer fired while databuf is empty");
        return;
    }

    if (buffer_len(_sendbuf) == 0)
        compress_databuf();
}

void
ProxySender::run_connect_timer()
{
    if (_state == STATE_BACKOFF)
        _state = STATE_IDLE;

    assert(_state == STATE_IDLE);

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0) {
        _log->strerror("socket");
        close();
        return;
    }

    // if a local address was provided, bind to it
    if (_has_local_addr) {
        if (bind(_sock, (struct sockaddr*)&_local_addr, sizeof(_local_addr)) == -1) {
            _log->strerror("bind(%s:%d)", inet_ntoa(_local_addr.sin_addr),
                ntohs(_local_addr.sin_port));
            close();
            return;
        }
    }

    // set non-blocking on socket
    int status = fcntl(_sock, F_GETFL, NULL);
    if (status < 0) {
        _log->strerror("fcntl(F_GETFL)");
        close();
        return;
    }

    status |= O_NONBLOCK;

    if (fcntl(_sock, F_SETFL, status) < 0) {
        _log->strerror("fcntl(F_SETFL)");
        close();
        return;
    }

    // prevent socket from throwing SIGPIPE signals
    int on = 1;
    if (setsockopt(_sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&on,
            sizeof(on)) < 0) {
        _log->strerror("setsockopt(SO_NOSIGPIPE)");
        close();
        return;
    }

    // select for writes (that's how completion of a connect() is signaled)
    add_select();

    if (_client) _client->add_fd(_sock, this);

    // finally ready to attempt the connect() call
    int rv = connect(_sock, (struct sockaddr*)&_remote_addr, sizeof(_remote_addr));
    if (rv == -1) {
        handle_connect_failure();
        return;
    }
    
    // else, rv=0 which means instant success (odd...)
    _log->info("connect() succeeded immediately to %s:%d",
        inet_ntoa(_remote_addr.sin_addr), ntohs(_remote_addr.sin_port));
    handle_connect_success();
}

size_t
ProxySender::serialize_packet(const Packet *p, u_char *cbuf, size_t maxlen)
{
    // we assume that tailroom is garbage and does not need to be sent
    size_t total_len = p->length() + sizeof(struct argos_net_clickpkt_msg);
    if (total_len > maxlen) return 0;

    struct argos_net_clickpkt_msg *msg = (struct argos_net_clickpkt_msg*)cbuf;
    msg->msgtype = htons(ARGOS_NET_CLICKPKT_MSGTYPE);
    msg->msglen = htonl(total_len);
    msg->packet_type = p->packet_type_anno();
    if (p->has_mac_header())
        msg->mac_offset = htonl(p->mac_header_offset());
    else
        msg->mac_offset = htonl(ARGOS_NET_CLICKPKT_UNDEF);
    if (p->has_network_header())
        msg->net_offset = htonl(p->network_header_offset());
    else
        msg->net_offset = htonl(ARGOS_NET_CLICKPKT_UNDEF);
    if (p->has_transport_header())
        msg->trans_offset = htonl(p->transport_header_offset());
    else
        msg->trans_offset = htonl(ARGOS_NET_CLICKPKT_UNDEF);

    // Timestamp::sec() returns an unknown type (can be 8-bytes!) so make sure
    // to cast appropriately
    uint32_t sec = (uint32_t)p->timestamp_anno().sec();
    msg->ts_sec = htonl(sec);
    msg->ts_usec = htonl(p->timestamp_anno().usec());

    assert(ARGOS_NET_CLICKPKT_ANNO_SIZE >= Packet::anno_size);
    memcpy(msg->anno, p->anno_u8(), Packet::anno_size);

    u_char *body = cbuf + sizeof(struct argos_net_clickpkt_msg);
    memcpy(body, p->data(), p->length());
    return total_len;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(buffer)
ELEMENT_REQUIRES(quicklz)
ELEMENT_REQUIRES(proxyclient)
ELEMENT_PROVIDES(proxysender)
