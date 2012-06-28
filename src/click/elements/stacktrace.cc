/*
 * stacktrace.{cc,hh} -- prints a stack trace to stderr on signals
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "stacktrace.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/userutils.hh>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
CLICK_DECLS

static int
parse_signal(const String &s)
{
#define CLICK_NSIG 32
    const char *signames[CLICK_NSIG] = {
        "?",
        "HUP",
        "INT",
        "QUIT",
        "ILL",
        "TRAP",
        "ABRT",
        "EMT",
        "FPE",
        "KILL",
        "BUS",
        "SEGV",
        "SYS",
        "PIPE",
        "ALRM",
        "TERM",
        "URG",
        "STOP",
        "TSTP",
        "CONT",
        "CHLD",
        "TTIN",
        "TTOU",
        "IO",
        "XCPU",
        "XFSZ",
        "VTALRM",
        "PROF",
        "WINCH",
        "INFO",
        "USR1",
        "USR2" };

    for (int j=0; j < CLICK_NSIG; j++) {
        if (strcmp(s.c_str(), signames[j]) == 0)
            return j;
    }
    
    int signum = -1;
    if (!cp_integer(s, &signum))
        return -1;
    else
        return signum;
#undef CLICK_NSIG
}

static int
print_header(int signum, int fd)
{
    // emulate snprintf()
    char cbuf[128] = "caught signal ??, stacktrace: ";
    cbuf[14] = ((signum/10) == 0) ? ' ' : ('0' + (signum/10));
    cbuf[15] = '0' + (signum % 10);

    // emulate strlen()
    size_t slen;
    for (slen=0; cbuf[slen] != '\0'; slen++) {}

    size_t written = 0;
    while (written < slen) {
        int rv = write(fd, cbuf + written, slen - written);
        if (rv == -1)
            return -1;
        written += rv;
    }
    return 0;
}

static volatile sig_atomic_t _stacktrace_in_progress = 0;

static void
signal_handler_exit_sig(int signum)
{
    // avoid mixing stack traces triggered by multiple signals
    if (!_stacktrace_in_progress) {
        _stacktrace_in_progress = 1;
        if (print_header(signum, STDERR_FILENO) == 0)
            (void) StackTrace::print_stack_trace(STDERR_FILENO, 1);
        _stacktrace_in_progress = 0;
    }
    _exit(128+signum);
}

static void
signal_handler_exit0(int signum)
{
    // avoid mixing stack traces triggered by multiple signals
    if (!_stacktrace_in_progress) {
        _stacktrace_in_progress = 1;
        if (print_header(signum, STDERR_FILENO) == 0)
            (void) StackTrace::print_stack_trace(STDERR_FILENO, 1);
        _stacktrace_in_progress = 0;
    }
    _exit(0);
}

static void
signal_handler_raise(int signum)
{
    // avoid mixing stack traces triggered by multiple signals
    if (!_stacktrace_in_progress) {
        _stacktrace_in_progress = 1;
        if (print_header(signum, STDERR_FILENO) == 0)
            (void) StackTrace::print_stack_trace(STDERR_FILENO, 1);
        _stacktrace_in_progress = 0;
    }
    raise(signum);
}

static void
signal_handler_return(int signum)
{
    // avoid mixing stack traces triggered by multiple signals
    if (!_stacktrace_in_progress) {
        _stacktrace_in_progress = 1;
        if (print_header(signum, STDERR_FILENO) == 0)
            (void) StackTrace::print_stack_trace(STDERR_FILENO, 1);
        _stacktrace_in_progress = 0;
    }
    return;
}

StackTrace::StackTrace() : _action(STACKTRACE_RAISE)
{
}

StackTrace::~StackTrace()
{
}

enum { H_SIGNAL };

void
StackTrace::add_handlers()
{
    add_write_handler("signal", write_handler, (void*)H_SIGNAL);
}

int
StackTrace::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool has_action = false;
    String action;
    int parsed = cp_va_kparse(conf, this, errh,
        "ACTION", cpkC, &has_action, cpString, &action,
        cpIgnoreRest, cpEnd);
    if (parsed < 0)
        return -1;

    if (has_action) {
        if (action.upper() == "EXIT")
            _action = STACKTRACE_EXIT_SIG;
        else if (action.upper() == "EXIT0")
            _action = STACKTRACE_EXIT_0;
        else if (action.upper() == "RAISE")
            _action = STACKTRACE_RAISE;
        else if (action.upper() == "RETURN")
            _action = STACKTRACE_RETURN;
    }

    for (int i=parsed; i < conf.size(); i++) {
        int signum = parse_signal(conf[i]);
        if (signum == -1)
            return errh->error("expected signal, not '%s'", conf[i].c_str());
        else
            _signals.push_back(signum);
    }

    return 0;
#undef CLICK_NSIG
}

int
StackTrace::initialize(ErrorHandler *errh)
{
    // could use master()->add_signal_handler() instead of click_signal but
    // I don't trust that it will always call us in the event of nasty signals
    // like ILL or SEGV
    void (*h)(int);

    switch (_action) {
    case STACKTRACE_EXIT_SIG:
        h = signal_handler_exit_sig;
        break;
    case STACKTRACE_EXIT_0:
        h = signal_handler_exit0;
        break;
    case STACKTRACE_RAISE:
        h = signal_handler_raise;
        break;
    case STACKTRACE_RETURN:
        h = signal_handler_return;
        break;
    default:
        return errh->error("unknown action (internal error): %d", _action);
    }

    for (int i=0; i < _signals.size(); i++)
        click_signal(_signals[i], h, true /* reset to SIG_DFL */);

    return 0;
}

int
StackTrace::print_stack_trace(int fd, int newline)
{
#define DIGIT_TO_HEX(c) (((c) < 10) ? ('0' + (c)) : ('a' + (c) - 10))
    
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
#define WRITE_POINTER_VAL(ba, ca)                                      \
    do {                                                               \
        (ca)[0] = '0';                                                 \
        (ca)[1] = 'x';                                                 \
        (ca)[2] = DIGIT_TO_HEX((ba)[0] >> 4);                          \
        (ca)[3] = DIGIT_TO_HEX((ba)[0] & 0xF);                         \
        (ca)[4] = DIGIT_TO_HEX((ba)[1] >> 4);                          \
        (ca)[5] = DIGIT_TO_HEX((ba)[1] & 0xF);                         \
        (ca)[6] = DIGIT_TO_HEX((ba)[2] >> 4);                          \
        (ca)[7] = DIGIT_TO_HEX((ba)[2] & 0xF);                         \
        (ca)[8] = DIGIT_TO_HEX((ba)[3] >> 4);                          \
        (ca)[9] = DIGIT_TO_HEX((ba)[3] & 0xF);                         \
    } while (0)
#else  /* ! (CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN) */
#define WRITE_POINTER_VAL(ba, ca)                                      \
    do {                                                               \
        (ca)[0] = '0';                                                 \
        (ca)[1] = 'x';                                                 \
        (ca)[2] = DIGIT_TO_HEX((ba)[3] >> 4);                          \
        (ca)[3] = DIGIT_TO_HEX((ba)[3] & 0xF);                         \
        (ca)[4] = DIGIT_TO_HEX((ba)[2] >> 4);                          \
        (ca)[5] = DIGIT_TO_HEX((ba)[2] & 0xF);                         \
        (ca)[6] = DIGIT_TO_HEX((ba)[1] >> 4);                          \
        (ca)[7] = DIGIT_TO_HEX((ba)[1] & 0xF);                         \
        (ca)[8] = DIGIT_TO_HEX((ba)[0] >> 4);                          \
        (ca)[9] = DIGIT_TO_HEX((ba)[0] & 0xF);                         \
    } while (0)
#endif  /* CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN */

#define WRITE_RETURN_ADDR(i)                                            \
    do {                                                                \
        char cbuf[32];                                                  \
        void *addr = __builtin_return_address(i);                       \
        u_char *bytes = (u_char*)&addr;                                 \
        cbuf[0] = ' ';                                                  \
        /* WRITE_POINTER_VAL should write exactly 10 characters */      \
        WRITE_POINTER_VAL(bytes, cbuf+1);                               \
        size_t slen = 11;                                               \
        size_t written = 0;                                             \
        while (written < slen) {                                        \
            int rv = write(fd, cbuf + written,                          \
                slen - written);                                        \
            if (rv == -1)                                               \
                return -1;                                              \
            written += rv;                                              \
        }                                                               \
        /* in my test program 0x1 was always the address of the */      \
        /* top stack, but click seems to start at 0x2, so we'll */      \
        /* just take a guess that the addr is <= 16 */                  \
        if (addr <= (void*)0x10)                                        \
            goto finished;                                              \
    } while (0)                                                         \

    WRITE_RETURN_ADDR(0);
    WRITE_RETURN_ADDR(1);
    WRITE_RETURN_ADDR(2);
    WRITE_RETURN_ADDR(3);
    WRITE_RETURN_ADDR(4);
    WRITE_RETURN_ADDR(5);
    WRITE_RETURN_ADDR(6);
    WRITE_RETURN_ADDR(7);
    WRITE_RETURN_ADDR(8);
    WRITE_RETURN_ADDR(9);
    WRITE_RETURN_ADDR(10);
    WRITE_RETURN_ADDR(11);
    WRITE_RETURN_ADDR(12);
    WRITE_RETURN_ADDR(13);
    WRITE_RETURN_ADDR(14);
    WRITE_RETURN_ADDR(15);
    WRITE_RETURN_ADDR(16);
    WRITE_RETURN_ADDR(17);
    WRITE_RETURN_ADDR(18);
    WRITE_RETURN_ADDR(19);
    WRITE_RETURN_ADDR(20);
    WRITE_RETURN_ADDR(21);
    WRITE_RETURN_ADDR(22);
    WRITE_RETURN_ADDR(23);
    WRITE_RETURN_ADDR(24);
    WRITE_RETURN_ADDR(25);
    WRITE_RETURN_ADDR(26);
    WRITE_RETURN_ADDR(27);
    WRITE_RETURN_ADDR(28);
    WRITE_RETURN_ADDR(29);
    WRITE_RETURN_ADDR(30);
    WRITE_RETURN_ADDR(31);
    WRITE_RETURN_ADDR(32);
    WRITE_RETURN_ADDR(33);
    WRITE_RETURN_ADDR(34);
    WRITE_RETURN_ADDR(35);
    WRITE_RETURN_ADDR(36);
    WRITE_RETURN_ADDR(37);
    WRITE_RETURN_ADDR(38);
    WRITE_RETURN_ADDR(39);
    WRITE_RETURN_ADDR(40);
    WRITE_RETURN_ADDR(41);
    WRITE_RETURN_ADDR(42);
    WRITE_RETURN_ADDR(43);
    WRITE_RETURN_ADDR(44);
    WRITE_RETURN_ADDR(45);
    WRITE_RETURN_ADDR(46);
    WRITE_RETURN_ADDR(47);
    WRITE_RETURN_ADDR(48);
    WRITE_RETURN_ADDR(49);
    WRITE_RETURN_ADDR(50);
    WRITE_RETURN_ADDR(51);
    WRITE_RETURN_ADDR(52);
    WRITE_RETURN_ADDR(53);
    WRITE_RETURN_ADDR(54);
    WRITE_RETURN_ADDR(55);
    WRITE_RETURN_ADDR(56);
    WRITE_RETURN_ADDR(57);
    WRITE_RETURN_ADDR(58);
    WRITE_RETURN_ADDR(59);
    WRITE_RETURN_ADDR(60);
    WRITE_RETURN_ADDR(61);
    WRITE_RETURN_ADDR(62);
    WRITE_RETURN_ADDR(63);
    WRITE_RETURN_ADDR(64);
    WRITE_RETURN_ADDR(65);
    WRITE_RETURN_ADDR(66);
    WRITE_RETURN_ADDR(67);
    WRITE_RETURN_ADDR(68);
    WRITE_RETURN_ADDR(69);
    WRITE_RETURN_ADDR(70);
    WRITE_RETURN_ADDR(71);
    WRITE_RETURN_ADDR(72);
    WRITE_RETURN_ADDR(73);
    WRITE_RETURN_ADDR(74);
    WRITE_RETURN_ADDR(75);
    WRITE_RETURN_ADDR(76);
    WRITE_RETURN_ADDR(77);
    WRITE_RETURN_ADDR(78);
    WRITE_RETURN_ADDR(79);
    WRITE_RETURN_ADDR(80);
    WRITE_RETURN_ADDR(81);
    WRITE_RETURN_ADDR(82);
    WRITE_RETURN_ADDR(83);
    WRITE_RETURN_ADDR(84);
    WRITE_RETURN_ADDR(85);
    WRITE_RETURN_ADDR(86);
    WRITE_RETURN_ADDR(87);
    WRITE_RETURN_ADDR(88);
    WRITE_RETURN_ADDR(89);
    WRITE_RETURN_ADDR(90);
    WRITE_RETURN_ADDR(91);
    WRITE_RETURN_ADDR(92);
    WRITE_RETURN_ADDR(93);
    WRITE_RETURN_ADDR(94);
    WRITE_RETURN_ADDR(95);
    WRITE_RETURN_ADDR(96);
    WRITE_RETURN_ADDR(97);
    WRITE_RETURN_ADDR(98);
    WRITE_RETURN_ADDR(99);
    WRITE_RETURN_ADDR(100);
    WRITE_RETURN_ADDR(101);
    WRITE_RETURN_ADDR(102);
    WRITE_RETURN_ADDR(103);
    WRITE_RETURN_ADDR(104);
    WRITE_RETURN_ADDR(105);
    WRITE_RETURN_ADDR(106);
    WRITE_RETURN_ADDR(107);
    WRITE_RETURN_ADDR(108);
    WRITE_RETURN_ADDR(109);
    WRITE_RETURN_ADDR(110);
    WRITE_RETURN_ADDR(111);
    WRITE_RETURN_ADDR(112);
    WRITE_RETURN_ADDR(113);
    WRITE_RETURN_ADDR(114);
    WRITE_RETURN_ADDR(115);
    WRITE_RETURN_ADDR(116);
    WRITE_RETURN_ADDR(117);
    WRITE_RETURN_ADDR(118);
    WRITE_RETURN_ADDR(119);
    WRITE_RETURN_ADDR(120);
    WRITE_RETURN_ADDR(121);
    WRITE_RETURN_ADDR(122);
    WRITE_RETURN_ADDR(123);
    WRITE_RETURN_ADDR(124);
    WRITE_RETURN_ADDR(125);
    WRITE_RETURN_ADDR(126);
    WRITE_RETURN_ADDR(127);

finished:
    if (newline) {
        // terminate with a newline character
        char c = '\n';
        if (write(fd, &c, 1) != 1)
            return -1;
    }

    return 0;
#undef WRITE_RETURN_ADDR
}

int
StackTrace::write_handler(const String &s_in, Element*, void *thunk,
    ErrorHandler *errh)
{
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_SIGNAL: {
        int signum = parse_signal(s_in);
        if (signum == -1)
            return errh->error("expected signal, not '%s'", s_in.c_str());
        if (raise(signum) != 0)
            return errh->error("raise: %s", strerror(errno));
        return 0;
    }
    default:
        return errh->error("internal error (bad thunk value)");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StackTrace)
