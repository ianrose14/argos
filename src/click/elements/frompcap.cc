/*
 * frompcap.{cc,hh} -- a streamlined implementation of fromdevice
 * Ian Rose
 */

#include <click/config.h>
#include "frompcap.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/bpf.h>

extern "C" {
static void
pcap_cb(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* data)
{
    FromPcap *frompcap = (FromPcap *)user;
    frompcap->handle_packet(pkthdr, data);
}
}
CLICK_DECLS


FromPcap::FromPcap() : _task(this)
{
    _ifname = "";
    _pcap = NULL;
    _promisc = false;
    _snaplen = 2046;
    _bpf_filter = "";
    _bpf_immediate = false;

    _filename = "";
    _fp = NULL;
    _buf = NULL;
    _got_file_header = false;

    _fd = -1;
    _burst = 1;
    _dlt = -1;
    _headroom = Packet::default_headroom;
    _headroom += (4 - (_headroom + 2) % 4) % 4; // default 4/2 alignment
    _limit = -1;
    _bufsize = 512*1024;

    _trace_cpu = false;
    _total_cpu_time = Timestamp(0);
    _start_cpu_time = Timestamp(0);
    _total_cycles = 0;
    _start_cycles = click_get_cycles();

    _last_ps_recv = 0;
    _last_ps_drop = 0;
    _recentered_ps_recv = 0;
    _recentered_ps_drop = 0;
    _mem_drop = 0;
    _total_count = 0;
}

FromPcap::~FromPcap()
{
    quit();
}

enum { H_KERN_RECV, H_KERN_DROP, H_DLT, H_AVG_CPU, H_AVG_CYCLES, H_RESET,
       H_RESET_AVGS };

void
FromPcap::add_handlers()
{
    // FromDevice.u uses "count" as its kernel_recv handler, so include an alias
    // with the same name for consistency
    add_read_handler("count", read_handler, (void*)H_KERN_RECV);
    add_read_handler("kernel_recv", read_handler, (void*)H_KERN_RECV);
    add_read_handler("kernel_drops", read_handler, (void*)H_KERN_DROP);
    add_data_handlers("mem_drops", Handler::OP_READ, &_mem_drop);
    add_read_handler("dlt", read_handler, (void*)H_DLT);
    add_read_handler("avg_cpu", read_handler, (void*)H_AVG_CPU);
    add_read_handler("avg_cycles", read_handler, (void*)H_AVG_CYCLES);
    // FromDevice.u uses "reset_counts" instead of "reset", so include an alias
    // with the same name for consistency
    add_write_handler("reset_counts", write_handler, (void*)H_RESET);
    add_write_handler("reset", write_handler, (void*)H_RESET);
    add_write_handler("reset_avgs", write_handler, (void*)H_RESET_AVGS);
}

int
FromPcap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dlt_name = "EN10MB";

    if (cp_va_kparse(conf, this, errh,
            "DEVNAME", cpkP, cpString, &_ifname,
            "FILENAME", 0, cpString, &_filename,
            "PROMISC", 0, cpBool, &_promisc,
            "SNAPLEN", 0, cpUnsigned, &_snaplen,
            "BPF_FILTER", 0, cpString, &_bpf_filter,
            "HEADROOM", 0, cpUnsigned, &_headroom,
            "DLT", 0, cpWord, &dlt_name,
            "BUFFER", 0, cpUnsigned, &_bufsize,
            "IMMEDIATE", 0, cpBool, &_bpf_immediate,
            "BURST", 0, cpInteger, &_burst,
            "TRACE_CPU", 0, cpBool, &_trace_cpu,
            "LIMIT", 0, cpInteger, &_limit,
            cpEnd) < 0)
	return -1;

    if ((_ifname == "") && (_filename == ""))
        return errh->error("must specify one of DEVNAME, FILENAME");

    if ((_ifname != "") && (_filename != ""))
        return errh->error("cannot specify both DEVNAME and FILENAME");

    if (_snaplen > 8190 || _snaplen < 14)
	return errh->error("SNAPLEN out of range");

    if ((_filename != "") && (_bpf_filter != ""))
        return errh->error("BPF filtering not supported for offline captures");

    if (_headroom > 8190)
	return errh->error("HEADROOM out of range");

    if (_filename != "") {
        _dlt = -1;  // defer until file is opened
    } else {
        _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
        if (_dlt < 0)
            return errh->error("bad datalink type");
    }

    if (_burst < 0)
	_burst = 0x7FFFFFFFU;
    else if (_burst == 0)
	return errh->error("BURST size 0, no packets will be read");

    return 0;
}

int
FromPcap::initialize(ErrorHandler *errh)
{
    if (_filename == "") {
        // open live capture
        char ebuf[PCAP_ERRBUF_SIZE];
        _pcap = pcap_create(_ifname.c_str(), ebuf);

        // note: pcap ebuf will contain the interface name on errors
        if (_pcap == NULL)
            return errh->error("pcap_create: %s", ebuf);

        if (pcap_set_snaplen(_pcap, _snaplen) != 0)
            return errh->error("pcap_set_snaplen: %s", pcap_geterr(_pcap));

        if (_promisc) {
            if (pcap_set_promisc(_pcap, 1) != 0)
                return errh->error("pcap_set_promisc: %s", pcap_geterr(_pcap));
        }

        if (pcap_set_buffer_size(_pcap, _bufsize) != 0)
            return errh->error("pcap_set_buffer_size: %s", pcap_geterr(_pcap));

        // not sure if this is required, but do it just in case
        if (pcap_set_timeout(_pcap, 0) != 0)
            return errh->error("pcap_set_timeout: %s", pcap_geterr(_pcap));

        if (pcap_activate(_pcap) != 0)
            return errh->error("pcap_activate: %s", pcap_geterr(_pcap));

        /*
         * the following calls must be done AFTER pcap_activate():
         * pcap_setfilter
         * pcap_setdirection
         * pcap_set_datalink
         * pcap_getnonblock
         * pcap_setnonblock
         * pcap_stats
         * all reads/writes
         */

        _fd = pcap_get_selectable_fd(_pcap);
        if (_fd == -1)
            return errh->error("pcap_get_selectable_fd returned -1");

        if (pcap_set_datalink(_pcap, _dlt) != 0)
            return errh->error("pcap_set_datalink: %s", pcap_geterr(_pcap));

        if (pcap_setnonblock(_pcap, 1, ebuf) != 0)
            return errh->error("pcap_setnonblock: %s", ebuf);

        // set BIOCIMMEDIATE if requested
        if (_bpf_immediate) {
            int r, yes = 1;
            if ((r = ioctl(_fd, BIOCIMMEDIATE, &yes)) == -1)
                return errh->error("%s: BIOCIMMEDIATE: %s", _ifname.c_str(),
                    strerror(errno));
            else if (r != 0)
                errh->warning("%s: BIOCIMMEDIATE returns %d", _ifname.c_str(), r);
        }

        // The pcap manpage stats that the netmask argument is only used to
        // detect IPv4 broadcast packets, and that a value of 0 can be supplied
        // if you don't care about that.  Since it doesn't make sense for use
        // queries to have anything to do with our local IP addresses, we don't
        // even both look up the netmask and just use 0 every time.
        bpf_u_int32 netmask = 0;
        int optimize = 1;

        // compile and then install the BPF filter
        struct bpf_program fcode;
        if (pcap_compile(_pcap, &fcode, _bpf_filter.c_str(), optimize, netmask) != 0)
            return errh->error("pcap_compile: %s", pcap_geterr(_pcap));
    
        int rv = pcap_setfilter(_pcap, &fcode);
        pcap_freecode(&fcode);  // always free code regardless of success
        if (rv != 0)
            return errh->error("pcap_setfilter: %s", pcap_geterr(_pcap));
    } else {
        // open offline capture

        if (_filename == "-") {
            _fp = stdin;
        } else {
            _fp = fopen(_filename.c_str(), "r");
            if (_fp == NULL)
                return errh->error("fopen(%s): %s", _filename.c_str(),
                    strerror(errno));
        }

        _fd = fileno(_fp);

        int status = fcntl(_fd, F_GETFL, NULL);
        if (status < 0)
            return errh->error("fcntl(F_GETFL)");
        status |= O_NONBLOCK;
        if (fcntl(_fd, F_SETFL, status) < 0)
            return errh->error("fcntl(F_SETFL)");

        _buf = buffer_create(_bufsize);
        if (_buf == NULL)
            return errh->error("buffer_create(%u): %s", _bufsize, strerror(errno));
    }

    add_select(_fd, SELECT_READ);

    ScheduleInfo::initialize_task(this, &_task, false, errh);

    if (_trace_cpu) {
        _start_cpu_time = Timestamp::now();
        _start_cycles = click_get_cycles();
    }

    return 0;
}

int
FromPcap::get_stats(u_int &kern_recv, u_int &kern_drop)
{
    if (_filename != "") {
        kern_recv = _total_count - _recentered_ps_recv;
        _last_ps_recv = _total_count;
        kern_drop = 0;
        return 0;
    }

    struct pcap_stat stats;
    if (pcap_stats(_pcap, &stats) < 0) {
	ErrorHandler::default_handler()->error("%{element}: pcap_stats: %s",
            this, pcap_geterr(_pcap));
        return -1;
    }

    kern_recv = stats.ps_recv - _recentered_ps_recv;
    kern_drop = stats.ps_drop - _recentered_ps_drop;

    _last_ps_recv = stats.ps_recv;
    _last_ps_drop = stats.ps_drop;
    return 0;
}

bool
FromPcap::run_task(Task *t)
{
#define START_CPU_TRACE()                                               \
    if (_trace_cpu) {                                                   \
        start_cycles = click_get_cycles();                              \
        struct timespec tspec;                                          \
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {                   \
            start = Timestamp(tspec);                                   \
        } else {                                                        \
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s", \
                this, strerror(errno));                                 \
        }                                                               \
    }                                                                   \

#define STOP_CPU_TRACE()                                                \
    if (_trace_cpu) {                                                   \
        struct timespec tspec;                                          \
        if (clock_gettime(CLOCK_PROF, &tspec) == 0) {                   \
            Timestamp elapsed = Timestamp(tspec) - start;               \
            _total_cpu_time += elapsed;                                 \
        } else {                                                        \
            ErrorHandler::default_handler()->error("%{element}: clock_gettime: %s", \
                this, strerror(errno));                                 \
        }                                                               \
        click_cycles_t x_cycles = click_get_cycles() - start_cycles;    \
        _total_cycles += x_cycles;                                      \
    }

    if (_limit >= 0 && _total_count >= (uint32_t)_limit) {
        quit();
        return false;
    }

    Timestamp start;
    click_cycles_t start_cycles;
    START_CPU_TRACE();

    int worked = 0;
    while (worked < _burst) {
        Packet *p = NULL;

        if (_pkts.size() == 0) {
            // read some packets from the file or BPF descriptor
            if (read_packet()) {
                assert(_pkts.size() > 0);
            }
        }

        if (_pkts.size() > 0) {
            p = _pkts.front();
            _pkts.pop_front();
            worked++;

            // end CPU timing here as we are about to execute a push() which
            // will transfer control to another element
            STOP_CPU_TRACE();

            output(0).push(p);

            // resume cpu timing
            START_CPU_TRACE();
        } else
            break;
    }

    if (_pkts.size() > 0) {
        if (t == NULL)
            _task.reschedule();
        else
            _task.fast_reschedule();
    }

    STOP_CPU_TRACE();

    return worked > 0;
}

void
FromPcap::selected(int)
{
    // if this is an offline capture, then read the file header if we haven't
    // yet
    if ((_filename != "") && !_got_file_header) {
        if (perform_read()) {
            if (buffer_len(_buf) >= sizeof(struct pcap_file_header)) {
                struct pcap_file_header *fh =
                    (struct pcap_file_header*)buffer_head(_buf);
                
                if (fh->magic == TCPDUMP_MAGIC) {
                    if (fh->version_major != PCAP_VERSION_MAJOR) {
                        click_chatter("%{element}: invalid pcap major version (%d)",
                            fh->version_major);
                        quit();
                        return;
                    }
                    _dlt = fh->linktype;
                    _swapped = false;
                }
                else if (SWAPLONG(fh->magic) == TCPDUMP_MAGIC) {
                    if (SWAPSHORT(fh->version_major) != PCAP_VERSION_MAJOR) {
                        click_chatter("%{element}: invalid pcap major version (%d)",
                            fh->version_major);
                        quit();
                        return;
                    }
                    _dlt = SWAPLONG(fh->linktype);
                    _swapped = true;
                }
                else {
                    click_chatter("%{element}: invalid pcap major version (%d)",
                        fh->version_major);
                    quit();
                    return;
                }

                int rv = buffer_discard(_buf, sizeof(struct pcap_file_header));
                assert(rv == 0);
                _got_file_header = true;
            }
            else {
                // not yet enough bytes read for the entire pcap_file_header
                return;
            }
        } else {
            // read failed
            return;
        }
    }

    (void) run_task(NULL);
}

/*
 * Private Methods
 */

// just create and initialize a Packet object, appending it to the packet list
// to be dealt with (i.e. pushed downstream) later
void
FromPcap::handle_packet(const struct pcap_pkthdr* h, const u_char* sp)
{
    _total_count++;

    int length = h->caplen;

    Packet *p;
    try {
        p = Packet::make(_headroom, sp, length, 0);
    }
    catch (std::bad_alloc &ex) {
        _mem_drop++;
        return;
    }

    // set annotations
    p->set_timestamp_anno(Timestamp::make_usec(h->ts.tv_sec, h->ts.tv_usec));
    SET_EXTRA_LENGTH_ANNO(p, h->len - length);
    _pkts.push_back(p);
}

void
FromPcap::quit()
{
    if (_fd != -1) {
        remove_select(_fd, SELECT_READ);
        _fd = -1;
    }
    if (_pcap != NULL) {
        pcap_close(_pcap);
        _pcap = NULL;
    }
    if (_fp != NULL) {
        fclose(_fp);
        _fp = NULL;
    }
    if (_buf != NULL) {
        buffer_destroy(_buf);
        _buf= NULL;
    }
    while (_pkts.size()) {
        _pkts.front()->kill();
        _pkts.pop_front();
    }
}

bool
FromPcap::perform_read()
{
    size_t space = buffer_remaining(_buf);
    if (space == 0) {
        buffer_compact(_buf);
        space = buffer_remaining(_buf);
    }

    if (space == 0) {
        click_chatter("%{element}: buffer overflow", this);
        quit();
        return false;
    }
    ssize_t len = read(_fd, buffer_tail(_buf), space);
    if (len == -1) {
        click_chatter("%{element}: read: %s", this, strerror(errno));
        quit();
        return false;
    }
    else if (len == 0) {
        // EOF
        quit();
        return false;
    }
    else {
        assert(len > 0);
        int rv = buffer_expand(_buf, len);
        assert(rv == 0);
        return true;
    }
}

bool
FromPcap::read_packet()
{
    if (_filename != "") {
        // offline capture

        // first try to read a packet directly out of the buffer
        if (read_packet_from_buf())
            return true;

        // if there isn't a full packet in the buffer, try to read() some more
        // data
        if (perform_read()) {
            // now that we have read some more data into the buffer, try again
            // to read a packet directly out of the buffer
            return read_packet_from_buf();
        } else {
            // read failed
            return false;
        }
    } else {
        // live capture
        int cnt = -1;
        int rv = pcap_dispatch(_pcap, cnt, pcap_cb, (u_char *)this);
        if (rv == 0) {
            // read timeout (theoretically should never happen)
            return false;
        } else if (rv > 0) {
            return true;
        } else {
            ErrorHandler::default_handler()->error("%{element}: pcap_dispatch: %s",
                this, pcap_geterr(_pcap));
            return false;
        }
    }
}

bool
FromPcap::read_packet_from_buf()
{
    size_t len = buffer_len(_buf);

    // is there a complete packet header?
    if (len < sizeof(struct pcap_pkthdr))
        return false;

    struct pcap_pkthdr *pkthdr = (struct pcap_pkthdr*)buffer_head(_buf);
    struct pcap_pkthdr swapped_hdr;

    if (_swapped) {
        swapped_hdr.ts.tv_sec = SWAPLONG(pkthdr->ts.tv_sec);
        swapped_hdr.ts.tv_usec = SWAPLONG(pkthdr->ts.tv_usec);
        swapped_hdr.caplen = SWAPLONG(pkthdr->caplen);
        swapped_hdr.len = SWAPLONG(pkthdr->len);
        pkthdr = &swapped_hdr;
    }

    size_t full_pkt_len = sizeof(struct pcap_pkthdr) + pkthdr->caplen;

    if (len < full_pkt_len)
        return false;

    handle_packet(pkthdr, buffer_head(_buf) + sizeof(struct pcap_pkthdr));
    int rv = buffer_discard(_buf, full_pkt_len);
    assert(rv == 0);
    return true;
}

String
FromPcap::read_handler(Element* e, void *thunk)
{
    FromPcap* elt = static_cast<FromPcap*>(e);
    u_int kern_recv, kern_drop;

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_KERN_RECV:
        if (elt->get_stats(kern_recv, kern_drop) == 0)
            return String(kern_recv);
        else
            return String(elt->_last_ps_recv);

    case H_KERN_DROP:
        if (elt->get_stats(kern_recv, kern_drop) == 0)
            return String(kern_drop);
        else
            return String(elt->_last_ps_drop);

    case H_DLT:
        return String(pcap_datalink_val_to_name(elt->_dlt));

    case H_AVG_CPU: {
        double elapsed = (Timestamp::now() - elt->_start_cpu_time).doubleval();
        if (elapsed == 0)
            return String("0");
        char cbuf[32];
        double ratio = elt->_total_cpu_time.doubleval() / elapsed;
        snprintf(cbuf, sizeof(cbuf), "%.4f", ratio);
        return String(cbuf);
    }
    case H_AVG_CYCLES: {
        click_cycles_t elapsed = click_get_cycles() - elt->_start_cycles;
        if (elapsed == 0)
            return String("0");
        char cbuf[32];
        double ratio = elt->_total_cycles / (double)elapsed;
        snprintf(cbuf, sizeof(cbuf), "%.4f", ratio);
        return String(cbuf);
    }
    default:
        return "internal error (bad thunk value)";
    }
}

int
FromPcap::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    FromPcap* elt = static_cast<FromPcap*>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_RESET:
        elt->_recentered_ps_recv = elt->_last_ps_recv;
        elt->_recentered_ps_drop = elt->_last_ps_drop;
        elt->_mem_drop = 0;
        return 0;
    case H_RESET_AVGS:
        elt->_total_cpu_time = Timestamp(0);
        elt->_start_cpu_time = Timestamp::now();
        elt->_total_cycles = 0;
        elt->_start_cycles = click_get_cycles();
        return 0;
    default:
        return errh->error("invalid thunk");
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(FromPcap)
ELEMENT_LIBS(-L../build/lib -lpcap)
