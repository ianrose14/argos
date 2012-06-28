/*
 * snort.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */
#include <click/config.h>
#include "snort.hh"
#include <click/confparse.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "snort/spo_alert_unixsock.h"
#include "../setsniffer.hh"
CLICK_DECLS

// from libpcap/savefile.c
#ifndef TCPDUMP_MAGIC
#define TCPDUMP_MAGIC 0xa1b2c3d4
#endif

Snort::Snort()
    : _snort_pid(0), _snort_stdin(-1), _snort_stdout(NULL), _snort_stderr(NULL),
      _dlt(-1), _snaplen(4096), _next_packet(NULL),
      _sockfile(""), _sock(0), _portscan_window(60*60),
      _task(this), _timer(this), _end_h(NULL), _db(NULL), _log(NULL)
{
}

Snort::~Snort()
{
    if (_end_h != NULL) delete _end_h;
    if (_log != NULL) delete _log;
}

enum { H_CLOSE, H_KILL, H_QUIT, H_STOP };

void
Snort::add_handlers()
{
    add_write_handler("close", write_handler, (void*)H_CLOSE, 0);
    add_write_handler("kill", write_handler, (void*)H_KILL, 0);
    add_write_handler("quit", write_handler, (void*)H_QUIT, 0);
    add_write_handler("stop", write_handler, (void*)H_STOP, 0);
    add_task_handlers(&_task);
}

void
Snort::cleanup(CleanupStage)
{
    if (_sock > 0)
        (void) close(_sock);

    // if we got far enough into the initialization for _sockfile to have a
    // value, try to unlink the file in case it was created
    if (_sockfile.length() > 0)
        (void) unlink(_sockfile.c_str());

    if (_snort_pid > 0) {
        StoredErrorHandler errh = StoredErrorHandler();
        if (signal_snort_proc(SIGTERM, &errh) < 0) {
            if (errh.has_error())
                click_chatter("%{element}: %s", this, errh.get_last_error().c_str());
        }
    }
}

int
Snort::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool stop = false;
    String logdir = ".", config;
    String dlt_name = "EN10MB";
    Element *elt = NULL;
    String loglevel, netlog;
    String logelt = "loghandler";
    String snort_argstr = "";

    if (cp_va_kparse(conf, this, errh,
            "EXE", cpkP+cpkM, cpString, &_snort_exe,
            "CONF", cpkP+cpkM, cpString, &config,
            "LOGDIR", 0, cpFilename, &logdir,
            "ADDL_ARGS", 0, cpString, &snort_argstr,
            "DLT", 0, cpString, &dlt_name,
            "SNAPLEN", 0, cpUnsigned, &_snaplen,
            "PORTSCAN_WINDOW", 0, cpTimestamp, &_portscan_window,
            "STOP", 0, cpBool, &stop,
            "END_CALL", 0, cpHandlerCallPtrWrite, &_end_h,
            "DB", 0, cpElement, &elt,
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

    // check that elt is a pointer to a PostgreSQL element (if specified at all)
    if (elt != NULL) {
        _db = (PostgreSQL*)elt->cast("PostgreSQL");
        if (_db == NULL)
            return errh->error("DB element is not an instance of type PostgreSQL");
    }

    _sockfile = logdir + "/snort_alert";

    struct sockaddr_un addr;
    if (_sockfile.length() >= (int)sizeof(addr.sun_path))
        return errh->error("sock-file path too long: %s", _sockfile.c_str());

    cp_spacevec(snort_argstr, _snort_args);
    _snort_args.push_back("-c");
    _snort_args.push_back(config);
    _snort_args.push_back("-r");
    _snort_args.push_back("-");
    _snort_args.push_back("-A");
    _snort_args.push_back("unsock");
    _snort_args.push_back("-l");
    _snort_args.push_back(logdir);

    String s = "mkdir -p " + logdir;
    int rv = system(s.c_str());
    if (rv < 0)
        return errh->error("mkdir failed (%d): %s", rv, s.c_str());

    _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
    if (_dlt < 0)
        return errh->error("bad datalink type");

    if (stop && _end_h)
        return errh->error("'END_CALL' and 'STOP' are mutually exclusive");
    else if (stop)
        _end_h = new HandlerCall(name() + ".quit");

    return 0;
}

int
Snort::initialize(ErrorHandler *errh)
{
    ScheduleInfo::initialize_task(this, &_task, true, errh);
    _signal = Notifier::upstream_empty_signal(this, 0, &_task);
    _timer.initialize(this);

    // check handler call
    if (_end_h && _end_h->initialize_write(this, errh) < 0)
        return -1;

    // create the unix socket that snort will write alerts to
    _sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (_sock < 0)
        return errh->error("socket: %s", strerror(errno));

    struct sockaddr_un addr;
    assert(_sockfile.length() < (int)sizeof(addr.sun_path));  // already checked

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, _sockfile.c_str(), sizeof(addr.sun_path));
    (void) unlink(addr.sun_path);
    // NOTE: many socket guides use the following which does not work due to
    // differences in the sockaddr_un definition between FreeBSD and Linux:
    // "len = strlen(local.sun_path) + sizeof(local.sun_family);"
    int len = sizeof(struct sockaddr_un);
    if (bind(_sock, (struct sockaddr *)&addr, len) != 0)
        return errh->error("bind: %s", strerror(errno));

    _log->debug("unix socket bound to %s", addr.sun_path);

    // create the snort command that we will exec to
    String cmd = _snort_exe;
    char **argv = (char**)malloc(sizeof(char*)*(2 + _snort_args.size()));
    argv[0] = strdup(_snort_exe.c_str());
    for (int i=0; i < _snort_args.size(); i++) {
        argv[i+1] = strdup(_snort_args[i].c_str());
        cmd = cmd + " " + String(argv[i+1]);
    }
    argv[1 + _snort_args.size()] = NULL;

    _log->debug("forking: %s", cmd.c_str());

    add_select(_sock, SELECT_READ);

    // create pipes and then fork a Snort process
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];
    if ((pipe(stdin_pipe) != 0) || (pipe(stdout_pipe) != 0) ||
        (pipe(stderr_pipe) != 0))
        return errh->error("pipe: %s", strerror(errno));

    int status = fcntl(stdin_pipe[1], F_GETFL, NULL);
    if (status < 0)
        return errh->error("fcntl(F_GETFL): %s", strerror(errno));

    status |= O_NONBLOCK;

    if (fcntl(stdin_pipe[1], F_SETFL, status) < 0)
        return errh->error("fcntl(F_SETFL): %s", strerror(errno));

    int pid = fork();
    if (pid == -1)
        return errh->error("fork: %s", strerror(errno));

    if (pid == 0) {
        // I am the child - copy pipes onto standard streams, then exec snort
        close(stdin_pipe[1]);   /* close write-end of stdin */
        close(stdout_pipe[0]);  /* close read-end of stdout */
        close(stderr_pipe[0]);  /* close read-end of stderr */

        dup2(stdin_pipe[0], STDIN_FILENO);    /* copy read-end of stdin */
        dup2(stdout_pipe[1], STDOUT_FILENO);  /* copy write-end of stdout */
        dup2(stderr_pipe[1], STDERR_FILENO);  /* copy write-end of stderr */

        close(stdin_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        execv(_snort_exe.c_str(), argv);

        // if execv returns, an error occurred (report to stderr)
        int errnum = errno;

        stderr = fdopen(STDERR_FILENO, "w");
        if (stderr == NULL) {
            fprintf(stderr, "fdopen: %s\n", strerror(errno));
            _exit(1);
        }

        fprintf(stderr, "execv: %s\n", strerror(errnum));
        fflush(stderr);
        _exit(1);
    }

    // else, I am the parent
    _log->info("snort pid %d forked", pid);
    _snort_pid = pid;

    close(stdin_pipe[0]);   // close read-end of stdin
    close(stdout_pipe[1]);  // close write-end of stdout
    close(stderr_pipe[1]);  // close write-end of stderr

    _snort_stdin = stdin_pipe[1];
    _snort_stdout = fdopen(stdout_pipe[0], "r");
    _snort_stderr = fdopen(stderr_pipe[0], "r");

    if ((_snort_stdout == NULL) || (_snort_stderr == NULL))
        return errh->error("fdopen of pipe to child: %s", strerror(errno));

    add_select(_snort_stdin, SELECT_WRITE);
    add_select(fileno(_snort_stdout), SELECT_READ);
    add_select(fileno(_snort_stderr), SELECT_READ);

    // write the file header to snort before any packets
    struct pcap_file_header hdr;
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;  // always 0
    hdr.sigfigs = 0;   // always 0
    hdr.snaplen = _snaplen;

    // Technically this is supposed to be a LINKTYPE value, NOT a DLT value;
    // libpcap goes through some hijinx mapping between these 2 sets of
    // constants to try to deal with platform differences in the DLT values and
    // such.  But for most values they are the same so we just use the DLT value
    // and call it a day (this is what Click's ToDump element does too).
    hdr.linktype = _dlt;

    size_t l = 0;
    while (l < sizeof(hdr)) {
        int rv = write(_snort_stdin, (char*)&hdr + l, sizeof(hdr) - l);
        if (rv < 0) {
            if (errno == EAGAIN) {
                // hackish, but should never happen in practice
                usleep(10*1000);
            }
            return errh->error("write of pcap file header to child: %s",
                strerror(errno));
        } else {
            l += rv;
        }
    }

    return 0;
}

bool
Snort::run_task(Task*)
{
    bool did_work = false;

    // it is possible (through race conditions) for this task to be run after
    // Snort's stdin has already been closed, so check for that
    if (_snort_stdin == -1)
        return false;

    if (_next_packet == NULL) {
        _next_packet = input(0).pull();
        if (_next_packet != NULL) {
            _next_pkthdr.ts = _next_packet->timestamp_anno().timeval();
            _next_pkthdr.len = _next_packet->length() + EXTRA_LENGTH_ANNO(_next_packet);
            _next_pkthdr.caplen = _next_packet->length();
            _header_written = 0;
            _body_written = 0;

            const struct click_ether *ether = (const struct click_ether*)_next_packet->data();
            if (_next_packet->length() < sizeof(*ether)) {
                // bad packet
                _log->error("bad ethernet packet received (len=%d)", _next_packet->length());
                _next_packet->kill();
                _next_packet = NULL;
                return true;
            }

            if (ether->ether_type == ETHERTYPE_IP) {
                const struct click_ip *ip = (const struct click_ip*)(_next_packet->data() + sizeof(*ether));
                if (_next_packet->length() < (sizeof(*ether) + sizeof(*ip))) {
                    // bad packet
                    _log->error("bad IP packet received (len=%d)", _next_packet->length());
                    _next_packet->kill();
                    _next_packet = NULL;
                    return true;
                }

                IPAddress src_ip = IPAddress(ip->ip_src);
                IPAddress dst_ip = IPAddress(ip->ip_dst);
                EtherAddress src_ether = EtherAddress(ether->ether_shost);

                // todo: run_timer -> clean out old entries of _src_info

                StoredErrorHandler errh;
                int32_t sniffer_id = 0;
                if (SetSniffer::parse_sniffer_id(_next_packet, &sniffer_id, &errh) != 0)
                    _log->error("parse_sniffer_id failed: %s", errh.get_last_error().c_str());

                IPDuo key = IPDuo(src_ip, dst_ip);

                SrcInfo *infop = _src_info.findp(key);
                if (infop == NULL) {
                    SrcInfo info = SrcInfo();
                    info.ether = src_ether;
                    info.capt_node_id = sniffer_id;
                    info.last_updated = _next_packet->timestamp_anno();
                    _src_info.insert(key, info);
                } else {
                    if (infop->ether != src_ether) {
                        // todo - change to debug level?
                        _log->warning("%s assignment changed from %s to %s",
                            key.unparse().c_str(),
                            infop->ether.unparse_colon().c_str(),
                            src_ether.unparse_colon().c_str());
                        infop->ether = src_ether;
                    }
                    infop->capt_node_id = sniffer_id;
                    infop->last_updated = _next_packet->timestamp_anno();
                }
            }

            did_work = true;
        } else {
            // no packet available
            if (_signal)
                _task.fast_reschedule();
            // else, wait for upstream notifier to reschedule this task
            return false;
        }
    }

    int rv = 0;

    // first send pcap packet header
    while (_header_written < sizeof(_next_pkthdr)) {
        rv = write(_snort_stdin, (&_next_pkthdr) + _header_written,
            sizeof(_next_pkthdr) - _header_written);

        if (rv < 0) {
            if (errno != EAGAIN) {
                _log->error("write to snort failed: %s", strerror(errno));
                close_snort_input();
            }

            // get notified when snort's stdin is writable again
            add_select(_snort_stdin, SELECT_WRITE);
            return did_work;
        } else {
            _header_written += rv;
            did_work = true;
        }
    }

    // now send the packet body itself
    while (_body_written < _next_packet->length()) {
        rv = write(_snort_stdin, _next_packet->data() + _body_written,
            _next_packet->length() - _body_written);

        if (rv < 0) {
            if (errno != EAGAIN) {
                _log->error("write to snort failed: %s", strerror(errno));
                close_snort_input();
            }

            // get notified when snort's stdin is writable again
            add_select(_snort_stdin, SELECT_WRITE);
            return did_work;
        } else {
            _body_written += rv;
            did_work = true;
        }
    }

    if (_signal)
        _task.fast_reschedule();

    // done with packet!
    _next_packet->kill();
    _next_packet = NULL;
    return true;
}

void
Snort::run_timer(Timer*)
{
    if (!check_snort_proc(0, false)) {
        // if process is dead then do not reschedule timer
        return;
    }

    Timestamp thresh = Timestamp::now() - Timestamp(24*60*60);  // 1 day

    // delete old source-info entries to prevent memory usage creep
    HashMap<IPDuo, SrcInfo>::iterator iter = _src_info.begin();
    for (; iter != _src_info.end(); iter++) {
        if (iter.value().last_updated < thresh) {
            // todo - change to debug after testing
            _log->warning("expiring SrcInfo for %s", iter.key().unparse().c_str());
            _src_info.remove(iter.key());
        }
    }

    if ((_snort_stdout == NULL) && (_snort_stderr == NULL)) {
        // process appears to be shutting down so reschedule timer with a short
        // interval so we can quickly detect when the process ends
        _timer.reschedule_after_msec(100);
    } else {
        // reschedule timer with a more leisurely interval
        _timer.reschedule_after_sec(60);
    }
}

void
Snort::selected(int fd)
{
    if (fd == _sock) {
        char cbuf[4096];
        ssize_t rlen = recv(_sock, cbuf, sizeof(cbuf), 0);
        if (rlen == -1) {
            _log->strerror("recv");
            return;
        }
        if (rlen == 0) {
            _log->warning("UNIX socket recv() returned 0");
            return;
        }

        if (rlen < (int)sizeof(Alertpkt)) {
            _log->error("Alertpkt received from Snort too small (%d)", rlen);
            return;
        }
        
        Alertpkt *alert = (Alertpkt*)cbuf;
        Timestamp ts = Timestamp(alert->pkth.ts);

        // as a special case, portscan detections create pseudo-packets as a
        // means of reporting alerts - these are normal IP packets with
        // ipproto=255 and the payload containing text describing the portscan
        if ((alert->event.sig_id == SNORT_PORTSCAN_SIG) &&
            (alert->event.classification == SNORT_PORTSCAN_CLASSIFICATION)) {
            const struct click_ip *ip = (const struct click_ip*)(alert->pkt + sizeof(struct click_ether));

            if (ip->ip_p != 255)
                _log->warning("Portscan packet has ip-proto %d (expected 255)", ip->ip_p);

            EtherAddress *src_ether = NULL;
            int *capt_node_id = NULL;

            IPAddress src_ip = IPAddress(ip->ip_src);
            IPAddress dst_ip = IPAddress(ip->ip_dst);
            IPDuo key = IPDuo(src_ip, dst_ip);

            SrcInfo *infop = _src_info.findp(key);
            if (infop != NULL) {
                src_ether = &infop->ether;
                capt_node_id = &infop->capt_node_id;

                // suppress duplicate portscan alerts
                Timestamp *last_scan = _last_portscan_alert.findp(*src_ether);
                if ((last_scan != NULL) && (ts < (*last_scan + _portscan_window))) {
                    // todo - change to debug level?
                    _log->info("suppressing repeated portscan alert for %s",
                        src_ether->unparse_colon().c_str());
                    return;
                }
            } else {
                _log->warning("Snort portscan packet has unknown IPDuo %s",
                    key.unparse().c_str());
            }

            int32_t priority_count = -1, connection_count = -1, ip_count = -1,
                port_count = -1, port_range_low = -1, port_range_high = -1;
            IPAddress ip_range_low, ip_range_high;

            size_t offset = sizeof(struct click_ether) + ip->ip_hl*4;
            char *txt = (char*)(alert->pkt + offset);
            char *start = txt;
            size_t len = alert->pkth.caplen - offset;
            for (size_t i=0; i < len; i++) {
                if (txt[i] != '\n')
                    continue;

                txt[i] = '\0';
                char *line = start;
                start = txt + i + 1;

                const char *prefix = "Priority Count:";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    priority_count = (int32_t)strtol(line + strlen(prefix), NULL, 10);
                    continue;
                }

                prefix = "Connection Count:";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    connection_count = (int32_t)strtol(line + strlen(prefix), NULL, 10);
                    continue;
                }

                prefix = "IP Count:";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    ip_count = (int32_t)strtol(line + strlen(prefix), NULL, 10);
                    continue;
                }

                prefix = "Scanned IP Range:";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    char *field = line + strlen(prefix);
                    while (isspace(field[0])) field++;
                    char *cp = strchr(field, ':');
                    if (cp == NULL) {
                        _log->error("invalid '%s' value from Snort portscan alert", prefix);
                        continue;
                    }
                    cp[0] = '\0';
                    ip_range_low = IPAddress(field);
                    ip_range_high = IPAddress(cp + 1);
                    continue;
                }

                prefix = "Port/Proto Count:";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    port_count = (int32_t)strtol(line + strlen(prefix), NULL, 10);
                    continue;
                }

                prefix = "Port/Proto Range:";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    char *field = line + strlen(prefix);
                    while (isspace(field[0])) field++;
                    char *cp = strchr(field, ':');
                    if (cp == NULL) {
                        _log->error("invalid '%s' value from Snort portscan alert", prefix);
                        continue;
                    }
                    cp[0] = '\0';
                    port_range_low = (int32_t)strtol(field, NULL, 10);
                    port_range_high = (int32_t)strtol(cp + 1, NULL, 10);
                    continue;
                }
            }

            _log->data("Snort portscan alert: ts=%d.%06u sig=%d msg=\"%s\" src=%s port-range=%d:%d",
                alert->pkth.ts.tv_sec, alert->pkth.ts.tv_usec, alert->event.sig_id,
                alert->alertmsg, src_ip.unparse().c_str(), port_range_low, port_range_high);

            if (_db)
                db_insert_portscan(ts, (char*)alert->alertmsg,
                    alert->event.sig_id, priority_count, connection_count,
                    src_ip, ip_count, ip_range_low, ip_range_high, port_count,
                    port_range_low, port_range_high, src_ether, capt_node_id);
        } else {
            _log->data("Snort alert: ts=%d.%06u sig=%d msg=\"%s\"",
                alert->pkth.ts.tv_sec, alert->pkth.ts.tv_usec, alert->event.sig_id,
                alert->alertmsg);

            if (_db)
                db_insert_alert(ts, (char*)alert->alertmsg,
                    alert->event.sig_id, alert->event.sig_rev,
                    alert->event.classification, alert->event.priority);

            WritablePacket *p;
            try {
                p = Packet::make(alert->pkt, alert->pkth.caplen);
            }
            catch (std::bad_alloc &ex) {
                // warning - could be quite spammy
                _log->warning("Packet::make() failed for len=%d", alert->pkth.caplen);
                return;
            }

            p->set_timestamp_anno(ts);
            p->set_mac_header(p->data());
            output(0).push(p);
        }

        return;
    }
    else if (fd == _snort_stdin) {
        // stop selecting until a write() call fails due to EAGAIN (in run_task)
        remove_select(_snort_stdin, SELECT_WRITE);

        // if there is a (previously pulled) packet ready and waiting to be
        // written to snort, then schedule the task to make this happen
        if (_next_packet != NULL)
            _task.reschedule();
        // else, no need to do anything - the task will be scheduled
        // automatically by the NotifierSignal when upstream packets are
        // available to be pulled
        return;
    }

    FILE **streamp;
    char line[1024];
    const char *src;
    line[0] = '\0';

    if ((_snort_stdout != NULL) && (fd == fileno(_snort_stdout))) {
        streamp = &_snort_stdout;
        src = "stdout";
    }
    else if ((_snort_stderr != NULL) && (fd == fileno(_snort_stderr))) {
        streamp = &_snort_stderr;
        src = "stderr";
    }
    else {
        // bad fd!  programming error?
        _log->critical("select for unknown fd: %d", fd);
        return;
    }

    // this is sloppy - we assume that Snort will only output complete lines
    // which may not be the case
    if (fgets(line, sizeof(line), *streamp) == NULL) {
        if (ferror(*streamp)) {
            assert(ferror(*streamp));
            _log->warning("error reading from Snort's %s", src);
        }

        remove_select(fd, SELECT_READ);
        (void) fclose(*streamp);
        *streamp = NULL;

        // if both stdout and stderr have hit EOF, then the process has
        // probably quit (or is doing so), so check it
        if ((_snort_stdout == NULL) && (_snort_stderr == NULL))
            _timer.schedule_now();
        return;
    }

    // strip leading and trailing spaces
    char *c = line;
    while (isspace(*c))
        c++;

    char *end = c + strlen(c) - 1;
    while ((end > c) && isspace(*end)) {
        *end = '\0';
        end--;
    }

    if (strlen(c) > 0)
        _log->info("Snort %s: %s", src, c);
}

bool
Snort::check_snort_proc(int sig, bool blocking)
{
    if (_snort_pid == 0) return false;  // process is not running

    int status;
    int options = blocking ? 0 : WNOHANG;
    pid_t rv = waitpid(_snort_pid, &status, options);

    if (rv == 0) {
        assert(!blocking);
        return true;  // process is still alive
    }

    if (rv == -1) {
        _log->warning("waitpid failed for snort pid %d: %s", _snort_pid,
            strerror(errno));
        return false;  // assume process is dead
    }

    // make sure that waitpid's status is what we expect
    assert(WIFSIGNALED(status) || WIFEXITED(status));

    if (WIFEXITED(status)) {
        _log->info("snort pid %d exitted normally with status %d",
            _snort_pid, WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)) {
        if (WTERMSIG(status) == sig) {
            // ok great - this is what we expect
            _log->debug("snort pid %d terminated by signal %d as expected",
                _snort_pid, sig);
        } else {
            _log->warning("snort pid %d terminated by signal %d", _snort_pid,
                WTERMSIG(status));
        }
    }

    _snort_pid = 0;
    if (_snort_stdin != -1) {
        remove_select(_snort_stdin, SELECT_WRITE);
        (void) close(_snort_stdin);
    }
    if (_snort_stdout != NULL) {
        remove_select(fileno(_snort_stdout), SELECT_READ);
        (void) fclose(_snort_stdout);
    }
    if (_snort_stderr != NULL) {
        remove_select(fileno(_snort_stderr), SELECT_READ);
        (void) fclose(_snort_stderr);
    }

    // now that the process has quit, perform the END_CALL if one was specified
    if (_end_h != NULL) {
        StoredErrorHandler errh = StoredErrorHandler();
        if (_end_h->call_write(&errh) < 0)
            if (errh.has_error())
                _log->error("END_CALL handler: %s", errh.get_last_error().c_str());
    }

    return false;  // process is now dead
}

void
Snort::close_snort_input()
{
    if (_snort_stdin == -1) return;  // ignore repeated calls

    remove_select(_snort_stdin, SELECT_WRITE);
    _task.unschedule();

    if (close(_snort_stdin) != 0)
        _log->error("close(stdin) to snort: %s", strerror(errno));
    _snort_stdin = -1;
}

void
Snort::db_insert_alert(const Timestamp &ts, const char *msg, uint32_t sig_id,
    uint32_t sig_rev, uint32_t classification, uint32_t priority)
{
    Vector<const char*> values;

    // note - neither raw_node_id nor agg_node_id columns are used because we
    // currently have no way to know the sniffer-id from packets spit out by
    // Snort
    static const String query = String("INSERT INTO snort_alerts"
        " (timestamp, message, sig_id, sig_rev, classification, priority)"
        " VALUES"
        " (timestamptz 'epoch' + $1 * interval '1 second', $2, $3, $4, $5, $6);");

    String ts_str = ts.unparse();
    String sig_id_str = String(sig_id);
    String sig_rev_str = String(sig_rev);
    String classification_str = String(classification);
    String priority_str = String(priority);

    values.push_back(ts_str.c_str());
    values.push_back(msg);
    values.push_back(sig_id_str.c_str());
    values.push_back(sig_rev_str.c_str());
    values.push_back(classification_str.c_str());
    values.push_back(priority_str.c_str());

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0) {
        StringAccum sa;
        for (int i=0; i < values.size(); i++)
            sa << String(values[i]) << " | ";
        _log->error("db_insert_alert failed: %s  (args: %s)",
            errh.get_last_error().c_str(), sa.take_string().c_str());
    }
    else if (rv == 1)
        _log->debug("1 row inserted for sig_id %d", sig_id);
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for dig_id %d", rv, sig_id);
}

void
Snort::db_insert_portscan(const Timestamp &ts, const char *msg, uint32_t sig_id,
    int32_t priority_count, int32_t connection_count, IPAddress src_ip,
    int32_t ip_count, IPAddress ip_range_low, IPAddress ip_range_high,
    int32_t port_count, int32_t port_range_low, int32_t port_range_high,
    EtherAddress *src_ether, int *capt_node_id)
{
    Vector<const char*> values;

    static const String query = String("INSERT INTO snort_portscans"
        " (timestamp, message, sig_id, priority_count, connection_count, src_ip"
        ", ip_count, ip_range_low, ip_range_high, port_count, port_range_low"
        ", port_range_high, src_ether, capt_node_id)"
        " VALUES"
        " (timestamptz 'epoch' + $1 * interval '1 second', $2, $3, $4, $5, $6"
        ", $7, $8, $9, $10, $11, $12, $13, $14);");

    String ts_str = ts.unparse();
    String sig_id_str = String(sig_id);
    String priority_count_str = String(priority_count);
    String connection_count_str = String(connection_count);
    String src_ip_str = src_ip.unparse();
    String ip_count_str = String(ip_count);
    String ip_range_low_str = ip_range_low.unparse();
    String ip_range_high_str = ip_range_high.unparse();
    String port_count_str = String(port_count);
    String port_range_low_str = String(port_range_low);
    String port_range_high_str = String(port_range_high);
    String src_ether_str;
    String capt_node_id_str;

    values.push_back(ts_str.c_str());
    values.push_back(msg);
    values.push_back(sig_id_str.c_str());
    values.push_back(priority_count_str.c_str());
    values.push_back(connection_count_str.c_str());
    values.push_back(src_ip_str.c_str());
    values.push_back(ip_count_str.c_str());
    values.push_back(ip_range_low_str.c_str());
    values.push_back(ip_range_high_str.c_str());
    values.push_back(port_count_str.c_str());
    values.push_back(port_range_low_str.c_str());
    values.push_back(port_range_high_str.c_str());

    if (src_ether == NULL) {
        values.push_back(NULL);
    } else {
        src_ether_str = src_ether->unparse_colon();
        values.push_back(src_ether_str.c_str());
    }

    if (capt_node_id == NULL) {
        values.push_back(NULL);
    } else {
        capt_node_id_str = String(*capt_node_id);
        values.push_back(capt_node_id_str.c_str());
    }

    StoredErrorHandler errh = StoredErrorHandler();
    int rv = _db->db_execute(query, values, &errh);
    if (rv < 0) {
        StringAccum sa;
        for (int i=0; i < values.size(); i++) 
            sa << String(values[i]) << " | ";
        _log->error("db_insert_portscan failed: %s  (args: %s)",
            errh.get_last_error().c_str(), sa.take_string().c_str());
    }
    else if (rv == 1)
        _log->debug("1 row inserted for sig_id %d", sig_id);
    else
        // should never affect 0 or >1 rows
        _log->error("%d rows inserted for dig_id %d", rv, sig_id);
}

int
Snort::signal_snort_proc(int sig, ErrorHandler *errh)
{
    if (_snort_pid == 0) return errh->error("snort process already dead");

    if (kill(_snort_pid, sig) != 0)
        return errh->error("kill(%d, %d): %s", _snort_pid, sig, strerror(errno));
    
    _log->debug("signal %d sent to snort pid %d", sig, _snort_pid);
    return 0;
}

int
Snort::write_handler(const String &, Element *e, void *thunk,
    ErrorHandler *errh)
{
    Snort *elt = static_cast<Snort *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_CLOSE:
        elt->close_snort_input();
        return 0;
    case H_KILL:
        return elt->signal_snort_proc(SIGKILL, errh);
    case H_QUIT:
        // it doesn't make much sense to include this handler on this element,
        // except that it allows easy implementation of the 'STOP true'
        // configuration option
        elt->router()->please_stop_driver();
        return 0;
    case H_STOP:
        return elt->signal_snort_proc(SIGTERM, errh);
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(Snort)
