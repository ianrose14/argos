/*
 * networkproxy.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "networkproxy.hh"
#include <click/element.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../iputil.hh"
#include "../wifiutil.hh"
#include "../argos/net_proto.h"
CLICK_DECLS


/*
 * NetworkProxy Methods
 */
NetworkProxy::NetworkProxy()
    : _compress_timer(this), _connect_timer(this), _task(this)
{
    _has_local_addr = false;
    _bind_local_addr = false;
    // _local_addr not initialized
    // _remote_addr not initialized
    _sock = -1;
    _cur_backoff = 5;   // seconds
    _init_backoff = 5;  // seconds
    _max_backoff = 60;  // seconds
    _send_delay = Timestamp::make_msec(100);
    // _signal not initialized
    _p = NULL;
    _burst = 1;
    _min_compress_len = 5*1024;  // default: 5 KB
    _databuf = NULL;
    _sendbuf = NULL;
    _sendbuf_aligned = true;
    _pkts_buffered = 0;
    _pkts_compressed = 0;
    _bytes_sent = 0;
    _pkts_sent = 0;
    _total_compress_in = 0;
    _total_compress_out = 0;
    _compressions_count = 0;
    _total_cpu_time = Timestamp(0);
    _start_cpu_time = Timestamp(0);
    _suppress_connect_errors = false;
    _trace_cpu = false;
    _log = NULL;
}

NetworkProxy::~NetworkProxy()
{
    close();

    // free various buffers
    if (_databuf != NULL) buffer_destroy(_databuf);
    if (_sendbuf != NULL) buffer_destroy(_sendbuf);

    if (_log != NULL) delete _log;
}

enum { H_COUNT, H_BYTE_COUNT, H_AVG_COMPRESS_RATE, H_AVG_COMPRESS_SIZE, H_AVG_CPU,
       H_DATABUFLEN, H_DST, H_DST_IP, H_DST_PORT, H_SENDBUFLEN, H_STATE,
       H_RESET, H_RESET_AVGS, H_CLOSE };

void
NetworkProxy::add_handlers()
{
    add_read_handler("count", read_handler, (void*)H_COUNT);
    add_read_handler("byte_count", read_handler, (void*)H_BYTE_COUNT);
    add_read_handler("avg_compress_rate", read_handler, (void*)H_AVG_COMPRESS_RATE);
    add_read_handler("avg_compress_size", read_handler, (void*)H_AVG_COMPRESS_SIZE);
    add_read_handler("avg_cpu", read_handler, (void*)H_AVG_CPU);
    add_read_handler("databuflen", read_handler, (void*)H_DATABUFLEN);
    add_read_handler("dst_ip", read_handler, (void*)H_DST_IP);
    add_read_handler("dst_port", read_handler, (void*)H_DST_PORT);
    add_read_handler("sendbuflen", read_handler, (void*)H_SENDBUFLEN);
    add_read_handler("state", read_handler, (void*)H_STATE);
    add_write_handler("dst", write_handler, (void*)H_DST);
    add_write_handler("reset", write_handler, (void*)H_RESET);
    add_write_handler("reset_counts", write_handler, (void*)H_RESET);
    add_write_handler("reset_avgs", write_handler, (void*)H_RESET_AVGS);
    add_write_handler("close", write_handler, (void*)H_CLOSE);
}

int
NetworkProxy::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dst, loglevel, netlog;
    String logelt = "loghandler";
    uint16_t port;
    IPAddress local_ip;

    // default bufsize = min(1 MB, <maximum allowed>)
    size_t bufsize = 1024*1024;
    if (ARGOS_NET_MAX_COMPRESS_LEN < bufsize) bufsize = ARGOS_NET_MAX_COMPRESS_LEN;

    if (cp_va_kparse(conf, this, errh,
            "DST", cpkP+cpkM, cpString, &dst,
            "PORT", cpkP+cpkM, cpTCPPort, &port,
            "LOCAL_IP", cpkC, &_has_local_addr, cpIPAddress, &local_ip,
            "BIND", 0, cpBool, &_bind_local_addr,
            "SENDBUF", 0, cpUnsigned, &bufsize,
            "BURST", 0, cpInteger, &_burst,
            "MIN_COMPRESS", 0, cpUnsigned, &_min_compress_len,
            "TRACE_CPU", 0, cpBool, &_trace_cpu,
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

    if (ip_lookup_address(dst, port, SOCK_STREAM, &_remote_addr, errh) != 0)
        return -EINVAL;

    if (_has_local_addr) {
        bzero(&_local_addr, sizeof(_local_addr));
        _local_addr.sin_family = AF_INET;
        _local_addr.sin_addr = local_ip.in_addr();
        // leave port as 0
    }

    if (_bind_local_addr && !_has_local_addr)
        return errh->error("BIND=true requires a LOCAL_IP parameter");

    if (bufsize > ARGOS_NET_MAX_COMPRESS_LEN)
        return errh->error("SENDBUF too big (max allowed is %u)",
            ARGOS_NET_MAX_COMPRESS_LEN);

    // along with the compressed data, sendbuf needs space for the
    // compress-message header
    size_t sendbufsize = bufsize + sizeof(struct argos_net_compress_msg);

    // data-buffer needs to be shrunk a little bit so that worst case QLZ
    // expansion will not cause the data to overflow the sendbuf
    size_t databufsize = bufsize - QLZ_MAX_INFLATE;
    if (bufsize <= QLZ_MAX_INFLATE)
        return errh->error("SENDBUF too small (min allowed is %u)",
            QLZ_MAX_INFLATE + 1);

    _databuf = buffer_create(databufsize);
    if (_databuf == NULL)
        return errh->error("buffer_create(%u): %s", databufsize, strerror(errno));

    _sendbuf = buffer_create(sendbufsize);
    if (_sendbuf == NULL)
        return errh->error("buffer_create(%u): %s", sendbufsize, strerror(errno));

    if (_burst < 0)
	_burst = 0x7FFFFFFFU;
    else if (_burst == 0)
	return errh->error("BURST size 0, no packets will be pulled");

    return 0;
}

int
NetworkProxy::initialize(ErrorHandler *errh)
{
    _state = STATE_IDLE;
    _compress_timer.initialize(this);
    _connect_timer.initialize(this);

    ScheduleInfo::initialize_task(this, &_task, true, errh);
    _signal = Notifier::upstream_empty_signal(this, 0, &_task);

    if (_trace_cpu)
        _start_cpu_time = Timestamp::now();

    return 0;
}

// to ease CPU tracing (i.e. so we don't have to deal with multiple points of
// exit from this function), the main functionality is in pull_inputs()
bool
NetworkProxy::run_task(Task*)
{
    // my testing seems to show that clock_gettime() is slightly faster than
    // getrusage()
    Timestamp start;
    if (_trace_cpu) {
        struct timespec tspec;
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
            start = Timestamp(tspec);
        } else {
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
                strerror(errno));
        }
    }

    int worked = 0;
    while (worked < _burst) {
        if (pull_inputs())
            worked++;
        else if (!_signal)
            goto out;
        else
            break;
    }

    // reschedule task UNLESS there is a packet buffered in _p because this
    // means that there isn't room in the databuf right now for this packet and
    // thus there is no reason trying to pull more packets until we clear the
    // buffer to make room
    if (_p == NULL)
        _task.fast_reschedule();
 out:

    if (_trace_cpu) {
        struct timespec tspec;
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
            Timestamp elapsed = Timestamp(tspec) - start;
            assert(elapsed >= 0);
            _total_cpu_time += elapsed;
        } else {
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
                strerror(errno));
        }
    }

    return worked > 0;
}

void
NetworkProxy::run_timer(Timer *timer)
{
    Timestamp start;
    if (_trace_cpu) {
        struct timespec tspec;
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
            start = Timestamp(tspec);
        } else {
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
                strerror(errno));
        }
    }

    if (timer == &_compress_timer)
        run_compress_timer();
    else if (timer == &_connect_timer)
        run_connect_timer();
    else {
        _log->error("run_timer(): unknown timer argument");
        close();
    }

    if (_trace_cpu) {
        struct timespec tspec;
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
            Timestamp elapsed = Timestamp(tspec) - start;
            assert(elapsed >= 0);
            _total_cpu_time += elapsed;
        } else {
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
                strerror(errno));
        }
    }
}

void
NetworkProxy::selected(int fd)
{
    Timestamp start;
    if (_trace_cpu) {
        struct timespec tspec;
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
            start = Timestamp(tspec);
        } else {
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
                strerror(errno));
        }
    }

    assert(fd == _sock);
    if (_state == STATE_CONNECTING) {
        handle_connect();
    } else {
        // first try a recv() in case we have selected readable due to an EOF
        char c;
        ssize_t len = recv(_sock, &c, 1, 0);

        if (len == -1) {
            switch (errno) {
            case EAGAIN:
                // that's fine - we were selected for writing, not reading
                handle_writable();
                break;

            case ECONNRESET:
            case ETIMEDOUT:
                // these errors can happen as a normal consequence of network
                // links going up and down so we don't report them as an error
                // (ETIMEDOUT is documented in the socket(2) man page, not
                // recv(2))
                _log->info("recv: %s", strerror(errno));
                remove_select(_sock, SELECT_READ);
                break;

            default:
                // all other errors are unexpected; they probably indicate a
                // programming error so we issue critical-level errors
                _log->critical("recv: %s", strerror(errno));
                remove_select(_sock, SELECT_READ);
                break;
            }
        }
        else if (len == 0) {
            // EOF from remote peer
            _log->info("EOF received");
            remove_select(_sock, SELECT_READ);
            reset_connection();
        }
        else {
            // data received from remote peer?!  this should never happen...
            assert(len > 0);
            _log->critical("%d bytes received (unexpected)", len);
            reset_connection();
        }
    }

    if (_trace_cpu) {
        struct timespec tspec;
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {
            Timestamp elapsed = Timestamp(tspec) - start;
            assert(elapsed >= 0);
            _total_cpu_time += elapsed;
        } else {
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s",
                strerror(errno));
        }
    }
}

int
NetworkProxy::set_destination(const String &hostname, uint16_t port, ErrorHandler *errh)
{
    if (ip_lookup_address(hostname, port, SOCK_STREAM, &_remote_addr, errh) != 0)
        return -EINVAL;

    if (_state != STATE_IDLE) {
        close();
        _state = STATE_IDLE;
        _suppress_connect_errors = false;

        if ((buffer_len(_databuf) > 0) || (buffer_len(_sendbuf) > 0))
            _connect_timer.schedule_after(_send_delay);
    }

    _log->info("destination changed to %s:%hu (ip: %s)", hostname.c_str(), port,
        inet_ntoa(_remote_addr.sin_addr));

    return 0;
}

/*
 * Private Static Class Methods
 */

size_t
NetworkProxy::serialize_packet(const Packet *p, u_char *cbuf, size_t maxlen)
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

String
NetworkProxy::read_handler(Element *e, void *thunk)
{
    const NetworkProxy *elt = static_cast<NetworkProxy *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);

    switch (which) {
    case H_COUNT:
        return String(elt->_pkts_sent);
    case H_BYTE_COUNT:
        return String(elt->_bytes_sent);
    case H_AVG_COMPRESS_RATE:
        if (elt->_total_compress_in == 0)
            return "0";
        else {
            // to avoid floating point operations, just multiply numerator by
            // 100 to give 2 digits of fraction
            uint64_t val = (elt->_total_compress_out*100)/elt->_total_compress_in;
            uint64_t remainder = val % 100;
            return String(val/100) + "." + String(remainder);
        }
    case H_AVG_COMPRESS_SIZE: {
        if (elt->_compressions_count == 0)
            return "0";
        else
            return String(elt->_total_compress_in/elt->_compressions_count);
    }
    case H_AVG_CPU: {
        double elapsed = (Timestamp::now() - elt->_start_cpu_time).doubleval();
        if (elapsed == 0)
            return String("0");
        char cbuf[32];
        double ratio = elt->_total_cpu_time.doubleval() / elapsed;
        snprintf(cbuf, sizeof(cbuf), "%.4f", ratio);
        return String(cbuf);
    }
    case H_DATABUFLEN:
        return String(buffer_len(elt->_databuf));
    case H_DST_IP:
        return elt->dst_ip().unparse();
    case H_DST_PORT:
        return String((int)elt->dst_port());
    case H_SENDBUFLEN:
        return String(buffer_len(elt->_sendbuf));
    case H_STATE:
        switch (elt->_state) {
        case STATE_IDLE:
            return "idle";
        case STATE_CONNECTING:
            return "connecting";
        case STATE_BACKOFF:
            return "backoff";
        case STATE_CONNECTED:
            return "connected";
        case STATE_DEAD:
            return "dead";
        default:
            return "unknown (code bug)";
        }
    default:
        return "internal error (bad thunk value)";
    }
}

int
NetworkProxy::write_handler(const String &s_in, Element *e, void *thunk, ErrorHandler *errh)
{
    NetworkProxy *elt = static_cast<NetworkProxy *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET:
        elt->_bytes_sent = 0;
        elt->_pkts_sent = 0;
        return 0;
    case H_RESET_AVGS:
        elt->_total_compress_in = 0;
        elt->_total_compress_out = 0;
        elt->_compressions_count = 0;
        elt->_total_cpu_time = Timestamp(0);
        elt->_start_cpu_time = Timestamp::now();
        return 0;
    case H_CLOSE:
        return elt->close();
    case H_DST: {
        int colon = s_in.find_left(':');
        if (colon == -1)
            return errh->error("expected input of form HOSTNAME:PORT");

        String hostname = s_in.substring(0, colon);
        uint16_t port;
        if (!cp_tcpudp_port(s_in.substring(colon+1), IP_PROTO_TCP, &port, elt))
            return errh->error("expected port number after colon");

        return elt->set_destination(hostname, port, errh);
    }
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

/*
 * Private Non-Static Class Methods
 */

int
NetworkProxy::close()
{
    if (_state == STATE_DEAD) return 0;

    const char *status_desc;
    if ((_state == STATE_IDLE) || (_state == STATE_CONNECTING) || (_state == STATE_BACKOFF))
        status_desc = "unconnected";
    else if (_state == STATE_CONNECTED)
        status_desc = "connected";
    else
        status_desc = "[unknown]";

    // close can be called (from the NetworkProxy destructor) before the _log is
    // ever created, so have to check if it exists yet
    if (_log != NULL)
        _log->info("closing (status=%s)", status_desc);

    if (_sock != -1) {
        remove_select(_sock, SELECT_WRITE);

        if (_sock != -1) {
            do {
                if (::close(_sock) == -1) {
                    if (errno == EINTR)
                        continue;
                    else
                        if (_log != NULL) _log->strerror("close");
                }
            } while (0);
        }

        _sock = -1;
    }

    _task.unschedule();
    _compress_timer.unschedule();
    _connect_timer.unschedule();

    _state = STATE_DEAD;
    return 0;
}

void
NetworkProxy::handle_connect()
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
            _log->critical("getpeername: %s", strerror(errno));
            reset_connection();
        }
    } else {
        // connect succeeded
        _log->info("connect() succeeded asynchronously to %s:%d",
            inet_ntoa(_remote_addr.sin_addr), ntohs(_remote_addr.sin_port));
        handle_connect_success();
    }
}

void
NetworkProxy::handle_connect_failure()
{
    switch (errno) {
        // these errors indicate some kind of programming error
    case EBADF:
    case ENOTSOCK:
    case EAFNOSUPPORT:
    case EFAULT:
        // fall through

        // generally, these are non-fatal, but should never happen in this
        // code; if they do, this indicates a programming error
    case EISCONN:
    case EALREADY:
        _log->critical("connect: %s", strerror(errno));
        reset_connection();
        return;
        
        // these are transient errors; we retry connecting
    case EADDRNOTAVAIL:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case EADDRINUSE:
    case ECONNRESET:
        // fall through

        // EAGAIN is NOT the same as EINPROGRESS; it means that the server's
        // connection backlog is full
    case EAGAIN:
        if (_suppress_connect_errors) {
            _log->debug("connect() failed with transient error: %s",
                strerror(errno));
        } else {
            _log->info("connect() failed with transient error: %s",
                strerror(errno));
            _log->info("silencing further connect() errors");
            _suppress_connect_errors = true;
        }
        reset_connection();
        return;

    case ENETUNREACH:
    case EHOSTUNREACH:
        // ENETUNREACH happens if there if some node on the routing path
        // (perhaps the localhost) can't get to the specified subnet - this
        // might indicate a routing problem.  I'm not sure what causes
        // EHOSTUNREACH, but I have seen it occur (rarely) on hosts that
        // otherwise seem to be working fine and can make successful connections
        // to some peers (but not others).  Perhaps this is due to problems
        // (like lost routes) with the kernel's routing table?.  For both of
        // these errors, we'll treat them as transient errors and hope that they
        // resolve themselves, but we log them at WARNING level due to their
        // rarity
        if (_suppress_connect_errors) {
            _log->debug("connect() failed: %s", strerror(errno));
        } else {
            _log->warning("connect() failed: %s", strerror(errno));
            _log->info("silencing further connect() errors");
            _suppress_connect_errors = true;
        }
        reset_connection();
        return;

        // these aren't really errors; the connect() should still work
    case EINPROGRESS:
        // this errno is ok if returned by connect() itself, but shouldn't be
        // returned via error slippage from a read() after a failed connect
        if (_state == STATE_CONNECTING) {
            _log->critical("read after failed connect: %s", strerror(errno));
            reset_connection();
            return;
        }
        // fall through

    case EINTR:
        _log->debug("connect() in progress (\"%s\")", strerror(errno));
        _state = STATE_CONNECTING;
        return;

    default:
        // unknown errno - probably a programming error or unexpected case
        if (_state == STATE_CONNECTING)
            _log->critical("read after failed connect: %s", strerror(errno));
        else
            _log->critical("connect: %s", strerror(errno));
        reset_connection();
        return;
    }
}

void
NetworkProxy::handle_connect_success()
{
    _state = STATE_CONNECTED;
    _suppress_connect_errors = false;

    // stop selecting for writes if the sendbuf is empty
    if (buffer_len(_sendbuf) == 0)
        remove_select(_sock, SELECT_WRITE);

    // select for reads only to detect EOFs sent from the remote peer - we don't
    // expect to actually receive any real data from the remote peer (and in
    // fact its an error if any IS received)
    add_select(_sock, SELECT_READ);

    // reset backoff upon successful connects
    _cur_backoff = _init_backoff;

    // schedule task (which takes care of pulling input) - note that even if the
    // databuf and sendbuf are both full, this is ok (run_task will safely
    // handle this situation)
    _task.reschedule();
}

void
NetworkProxy::handle_writable()
{
    size_t reqlen = buffer_len(_sendbuf);

    if (reqlen == 0) {
        _log->warning("selected() called when sendbuf.len=0");
        return;
    }

    ssize_t len = send(_sock, buffer_head(_sendbuf), reqlen, 0);
    if (len == -1) {
        switch (errno) {
        case ENOBUFS:
        case EPIPE:
            // these errors can occur "normally" due to typical, transient
            // errors (such as nodes being temporarily offline)
            _log->info("send: %s", strerror(errno));
            break;

        case ECONNREFUSED:
        case EHOSTUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
            // these errors are possible, but are rare and may indicate a more
            // serious problem
            _log->strerror("send");
            break;

        default:
            // anything else is unexpected and may indicate a programming error
            _log->critical("send: %s", strerror(errno));
            break;
        }

        reset_connection();
    } else {
        // send() succeeded
        assert(len > 0);

        int rv = buffer_discard(_sendbuf, len);
        assert(rv == len);
        _bytes_sent += len;

        // if sendbuf is now empty then we know we have sent the entire message;
        // update some stats and then try to refill the sendbuf (by compressing
        // data from the databuf)
        if (buffer_len(_sendbuf) == 0) {
            _log->debug("sent %d bytes successfully (drained send buffer)", len);

            // whenever sendbuf completely empties we know the buffer is aligned
            // again
            _sendbuf_aligned = true;

            _pkts_sent += _pkts_compressed;
            _pkts_compressed = 0;
            (void) try_compress_databuf();
        } else {
            _log->debug("sent %d bytes successfully (%d remaining in send buffer)",
                len, buffer_len(_sendbuf));

            // whenever sendbuf executes only a partial write (leaving some data
            // left in the buffer) it may now be unaligned, meaning we send just
            // the first part of a messge, leaving the remainder in the head of
            // the buffer
            _sendbuf_aligned = false;
        }

        // if sendbuf is STILL empty, stop selecting for writes
        if (buffer_len(_sendbuf) == 0) {
            remove_select(_sock, SELECT_WRITE);
        }
    }
}

bool
NetworkProxy::pull_inputs()
{
    // the task runs when the signal tells us that there are packets available
    // to pull from upstream

    if (_p == NULL)
        _p = input(0).pull();

    if (_p != NULL) {
        uint32_t space = buffer_remaining(_databuf);
        size_t reqlen = get_serialized_len(_p);

        if (reqlen > space) {
            // not enough space in the databuf to serialize this packet -
            // confirm that we will eventually have enough room (once the
            // databuf is totally empty)
            if (reqlen > buffer_size(_databuf)) {
                // serialized packet would bigger than the entire buffer!
                _log->warning("packet too big for databuf (%d bytes)", reqlen);
                _p->kill();
                _p = NULL;
                return false;
            } else {
                // there will be enough room once databuf drains; do not
                // reschedule task and "bump up" the compression timer to fire
                // immediately (since there is no point in waiting for more input
                // if we know now that none will come)
                assert(buffer_len(_databuf) > 0);
                _compress_timer.schedule_now();
                return false;
            }
        } else {
            // pull succeeded (or a packet was waiting in _p)

            // if we were configured with a LOCAL_IP, then set the MISC_IP
            // annotation (which we used as a source-address) to the our local
            // address; although an alternative is to let the receiver do this
            // (since it knows what address each packet it received from)
            // setting it on the sender is more reliable if NATs or tunnels are
            // in use
            if (_has_local_addr) {
                IPAddress src = IPAddress(_local_addr.sin_addr);
                SET_MISC_IP_ANNO(_p, src);
            }

            size_t written = serialize_packet(_p, buffer_tail(_databuf), space);
            assert(written == reqlen);
            int rv = buffer_expand(_databuf, written);
            assert(rv == (int)written);

            _pkts_buffered++;

            // if this packet is of type FASTROUTE (which is just used as a
            // marker by upstream elements that want to control the
            // NetworkProxy's behavior), then run the compression timer right
            // away - otherwise, start the compression timer if not already
            // running
            if (_p->packet_type_anno() == Packet::FASTROUTE) {
                _compress_timer.schedule_now();
            } else {
                if (!_compress_timer.scheduled())
                    _compress_timer.schedule_after(_send_delay);
            }

            _p->kill();
            _p = NULL;

            // initiate a connection attempt if this is the very first time that
            // we have pulled data
            if (_state == STATE_IDLE)
                _connect_timer.schedule_now();

            return true;
        }
    }

    return false;  // no packet returned by get_input
}

void
NetworkProxy::reset_connection()
{
    _state = STATE_BACKOFF;
    _connect_timer.reschedule_after_sec(_cur_backoff);
    remove_select(_sock, SELECT_WRITE);

    do {
        if (::close(_sock) == -1) {
            if (errno == EINTR)
                continue;
            else
                _log->strerror("close");
        }
    } while (0);

    _sock = -1;

    // exponentially increase backoff (note: timer already scheduled)
    _cur_backoff *= 2;
    if (_cur_backoff > _max_backoff)
        _cur_backoff = _max_backoff;

    // if sendbuf is unaligned, then we have to throw away all of its contents
    // as the head of the buffer might point to the middle of a message - this
    // is a bit inefficient (we are potentially losing a lot of messages) but
    // the assumption is that this is ok because connections shouldn't break
    // very often
    if (!_sendbuf_aligned) {
        buffer_empty(_sendbuf);
        _sendbuf_aligned = true;
        _pkts_compressed = 0;
    }
}

void
NetworkProxy::run_compress_timer()
{
    // the timer fires when its time to compress data from the databuf and
    // transfer it to the sendbuf
    if (buffer_len(_databuf) == 0) {
        _log->warning("timer fired while databuf is empty");
        return;
    }

    if (buffer_len(_sendbuf) == 0)
        (void) try_compress_databuf();

    // if the sendbuf is non-empty right now, do nothing - compress_databuf()
    // will be called once sendbuf empties out
}

void
NetworkProxy::run_connect_timer()
{
    if (_state == STATE_BACKOFF)
        _state = STATE_IDLE;

    assert(_state == STATE_IDLE);

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0) {
        _log->strerror("socket");
        reset_connection();
        return;
    }

    // if a local address was provided, bind to it
    if (_bind_local_addr) {
        if (bind(_sock, (struct sockaddr*)&_local_addr, sizeof(_local_addr)) == -1) {
            _log->strerror("bind(%s:%d)", inet_ntoa(_local_addr.sin_addr),
                ntohs(_local_addr.sin_port));
            reset_connection();
            return;
        }
    }

    // set non-blocking on socket
    int status = fcntl(_sock, F_GETFL, NULL);
    if (status < 0) {
        _log->strerror("fcntl(F_GETFL)");
        reset_connection();
        return;
    }

    status |= O_NONBLOCK;

    if (fcntl(_sock, F_SETFL, status) < 0) {
        _log->strerror("fcntl(F_SETFL)");
        reset_connection();
        return;
    }

    // prevent socket from throwing SIGPIPE signals
    int on = 1;
    if (setsockopt(_sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&on,
            sizeof(on)) < 0) {
        _log->strerror("setsockopt(SO_NOSIGPIPE)");
        reset_connection();
        return;
    }

    // select for writes (that's how completion of a connect() is signaled)
    add_select(_sock, SELECT_WRITE);

    // finally ready to attempt the connect() call
    int rv = connect(_sock, (struct sockaddr*)&_remote_addr, sizeof(_remote_addr));
    if (rv == -1) {
        handle_connect_failure();
        return;
    }
    
    // else, rv=0 which means instant success
    _log->info("connect() succeeded immediately to %s:%d",
        inet_ntoa(_remote_addr.sin_addr), ntohs(_remote_addr.sin_port));
    handle_connect_success();
}

bool
NetworkProxy::try_compress_databuf()
{
    size_t datalen = buffer_len(_databuf);
    
    // nothing to compress
    if (datalen == 0) return false;

    // if the compression timer is running, then do not touch the databuf as we
    // must still be in the waiting period after the data was first enqueued 
    if (_compress_timer.scheduled()) return false;

    // if _sendbuf is non-empty, then we are still in the process of sending the
    // current batch of compressed data so we aren't yet ready to compress more
    if (buffer_len(_sendbuf) > 0) return false;

    size_t space_avail = buffer_remaining(_sendbuf);
    uint32_t outlen;     // data-size after compression
    uint32_t write_len;  // total length of data written to sendbuf

    // if there isn't much in the data-buffer, don't bother try to compress it
    // (just copy it directly over)
    if (datalen < _min_compress_len) {
        size_t space_req = datalen + sizeof(struct argos_net_compress_msg);
        if (space_avail < space_req) {
            _log->critical("sendbuf unexpectedly too short at line %d."
                " datalen=%u, space_req=%u, space_avail=%u", __LINE__,
                datalen, space_req, space_avail);
            return false;
        }
        memcpy(buffer_tail(_sendbuf), buffer_head(_databuf), datalen);
        outlen = datalen;
        write_len = datalen;
    } else {
        size_t space_req = datalen + QLZ_MAX_INFLATE + 
            sizeof(struct argos_net_compress_msg);
        if (space_avail < space_req) {
            _log->critical("sendbuf unexpectedly too short at line %d."
                " datalen=%u, space_req=%u, space_avail=%u", __LINE__,
                datalen, space_req, space_avail);
            return false;
        }

        // where the compressed data should be written
        u_char *write_ptr = buffer_tail(_sendbuf) +
            sizeof(struct argos_net_compress_msg);

        struct argos_net_compress_msg *msg =
            (struct argos_net_compress_msg*)buffer_tail(_sendbuf);
        msg->msgtype = htons(ARGOS_NET_COMPRESS_MSGTYPE);
        msg->algorithm = ARGOS_NET_COMPRESS_QUICKLZ;
        msg->orig_len = htonl(datalen);
        // have to defer filling in msglen and crc32 fields

        outlen = qlz_compress(buffer_head(_databuf), (char*)write_ptr, datalen,
            _qlz_scratch);

        // sanity check: the outlen should always meet a minimum size
        if (outlen < QLZ_MIN_COMPRESS_SIZE) {
            _log->critical("qlz_compress returned outlen=%d from an inlen=%d"
                " (outlen should be >= %d)", outlen, datalen, QLZ_MIN_COMPRESS_SIZE);
        }

#ifdef ARGOS_NETPROXY_SAFE
        // sanity check: qlz_size_compressed and qlz_size_decompressed should
        // match expected values
        size_t qlz_decmp = qlz_size_decompressed((const char*)write_ptr);
        size_t qlz_cmp = qlz_size_compressed((const char*)write_ptr);
        if (qlz_decmp != datalen) {
            _log->critical("QuickLZ error.  data-len=%u, but qlz_size_decompressed=%u",
                datalen, qlz_decmp);
            return false;
        }
        if (qlz_cmp != outlen) {
            _log->critical("QuickLZ error.  out-len=%u, but qlz_size_compressed=%u",
                outlen, qlz_cmp);
            return false;
        }

        // calculate crc32 (only over the compressed data)
        uint32_t crc32 = wifi_calc_crc32(write_ptr, outlen);
        msg->crc32 = htonl(crc32);
        msg->crc32_used = 1;
#else
        msg->crc32_used = 0;
#endif  // #ifdef ARGOS_NETPROXY_SAFE

        // write back into the msglen field now that we know the total length
        write_len = sizeof(struct argos_net_compress_msg) + outlen;
        msg->msglen = htonl(write_len);

        // check for incompressible block (this is very common for small blocks,
        // and actually not that rare for [certain?] larger blocks either)
        if ((outlen > datalen) && (datalen >= 4096))
            _log->debug("incompressible block: inlen=%d, outlen=%d", datalen, outlen);
    }

    _log->debug("compressed %u bytes to %u (%u packets)", datalen, outlen,
        _pkts_buffered);

    // we update these variables even if the "compression" method was just a
    // memcpy because that should be reflected in the stats
    _total_compress_in += datalen;
    _total_compress_out += outlen;
    _compressions_count++;

    int rv = buffer_discard(_databuf, datalen);
    assert(rv == (int)datalen);
    rv = buffer_expand(_sendbuf, write_len);
    assert(rv == (int)write_len);

    _pkts_compressed = _pkts_buffered;
    _pkts_buffered = 0;

    // now that sendbuf is non-empty, select for writes
    add_select(_sock, SELECT_WRITE);

    // now that databuf is empty, its ok to pull more data into it
    if (_signal.active())
        _task.reschedule();

    return true;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(buffer quicklz IPUtil userlevel WifiUtil)
EXPORT_ELEMENT(NetworkProxy)
