/*
 * sshtunnel.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "sshtunnel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
CLICK_DECLS

SSHTunnel::SSHTunnel()
    : _ssh_pid(0), _ssh_stdout(NULL), _ssh_stderr(NULL), _sudo_uid(-1), _log(NULL)
{
}

SSHTunnel::~SSHTunnel()
{
    if (_log != NULL) delete _log;
}

enum { H_CONNECTED, H_CLOSE, H_OPEN };

void
SSHTunnel::add_handlers()
{
    add_read_handler("connected", read_handler, (void*)H_CONNECTED);
    add_write_handler("close", write_handler, (void*)H_CLOSE);
    add_write_handler("open", write_handler, (void*)H_OPEN);
}

void
SSHTunnel::cleanup(CleanupStage)
{
    if (_ssh_pid > 0) {
        StoredErrorHandler errh = StoredErrorHandler();
        if (signal_tunnel_process(SIGTERM, &errh) < 0) {
            if (errh.has_error())
                click_chatter("%{element}: %s", this, errh.get_last_error().c_str());
        }
    }
}

int
SSHTunnel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    uint16_t local_port, remote_port;
    String local_host, remote_host;
    String loglevel, netlog;
    String logelt = "loghandler";

    if (cp_va_kparse(conf, this, errh,
            "LOCAL_PORT", cpkP, cpTCPPort, &local_port,
            "REMOTE_HOST", cpkP, cpString, &remote_host,
            "REMOTE_PORT", cpkP, cpTCPPort, &remote_port,
            "LOCAL_HOST", 0, cpString, &local_host,
            "LOGIN", cpkM, cpString, &_ssh_login,
            "ID_FILE", cpkM, cpString, &_ssh_id_file,
            "SUDO", 0, cpInteger, &_sudo_uid,
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

    StringAccum sa;
    if (local_host != "")
        sa << local_host << ":";
    sa << local_port << ":" << remote_host << ":" << remote_port;
    _tunnel_cmd = sa.take_string();

    return 0;
}

int
SSHTunnel::initialize(ErrorHandler *)
{
    return 0;
}

void
SSHTunnel::selected(int fd)
{
    FILE **streamp;
    char line[1024];
    bool is_stderr;
    line[0] = '\0';

    if ((_ssh_stdout != NULL) && (fd == fileno(_ssh_stdout))) {
        streamp = &_ssh_stdout;
        is_stderr = false;
    }
    else if ((_ssh_stderr != NULL) && (fd == fileno(_ssh_stderr))) {
        streamp = &_ssh_stderr;
        is_stderr = true;
    }
    else {
        // bad fd!  programming error?
        _log->critical("select for unknown fd: %d", fd);
        return;
    }

    if (fgets(line, sizeof(line), *streamp) == NULL) {
        if (ferror(*streamp)) {
            assert(ferror(*streamp));
            _log->warning("error reading from SSH's %s",
                is_stderr ? "stderr" : "stdout");
        }

        // check to see if process has quit
        check_tunnel_process();

        remove_select(fd, SELECT_READ);
        (void) fclose(*streamp);
        *streamp = NULL;
        return;
    }

    char *c = line;
    while (isspace(*c))
        c++;

    char *end = c + strlen(c) - 1;
    while ((end > c) && isspace(*end)) {
        *end = '\0';
        end--;
    }

    if (strlen(c) > 0) {
        if (is_stderr)
            _log->warn("ssh stderr: %s", c);
        else
            _log->info("ssh stdout: %s", c);
    }
}

void
SSHTunnel::check_tunnel_process()
{
    int status;
    int options = WNOHANG;
    pid_t rv = waitpid(_ssh_pid, &status, options);

    if (rv == 0) return;  // process is still running

    if (rv == -1) {
        _log->error("waitpid failed for ssh pid %d: %s", _ssh_pid,
            strerror(errno));
        return;
    }

    // make sure that waitpid's status is what we expect
    assert(WIFSIGNALED(status) || WIFEXITED(status));

    if (WIFEXITED(status)) {
        _log->error("ssh pid %d exitted unexpectedly with status %d",
            _ssh_pid, WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)) {
        _log->error("ssh pid %d terminated by signal %d", _ssh_pid,
            WTERMSIG(status));
    }

    // clean up variables
    _ssh_pid = 0;
    if (_ssh_stdout != NULL) {
        remove_select(fileno(_ssh_stdout), SELECT_READ);
        (void) fclose(_ssh_stdout);
    }
    if (_ssh_stderr != NULL) {
        remove_select(fileno(_ssh_stderr), SELECT_READ);
        (void) fclose(_ssh_stderr);
    }
}

int
SSHTunnel::start_tunnel_process(ErrorHandler *errh)
{
    if (_ssh_pid != 0)
        return errh->error("ssh tunnel already running (pid=%d)", _ssh_pid);

    int stdout_pipe[2];
    int stderr_pipe[2];
    if ((pipe(stdout_pipe) != 0) || (pipe(stderr_pipe) != 0))
        return errh->error("pipe: %s", strerror(errno));

    pid_t pid = fork();
    if (pid == -1)
        return errh->error("fork: %s", strerror(errno));

    if (pid == 0) {
        // I am the child - copy pipes onto standard streams, then exec ssh
        close(stdout_pipe[0]);  // close read-end of stdout
        close(stderr_pipe[0]);  // close read-end of stderr

        dup2(stdout_pipe[1], STDOUT_FILENO);  // copy write-end of stdout
        dup2(stderr_pipe[1], STDERR_FILENO);  // copy write-end of stderr

        close(STDIN_FILENO);

        if (_sudo_uid >= 0) {
            String uidstr = "#" + String(_sudo_uid);
            execlp("sudo", "sudo", "-u", uidstr.c_str(),
                "ssh", "-N", "-a", "-x", "-q", "-L", _tunnel_cmd.c_str(),
                "-i", _ssh_id_file.c_str(),
                "-o", "StrictHostKeyChecking=no", _ssh_login.c_str(), NULL);
        } else {
            execlp("ssh", "ssh", "-N", "-a", "-x", "-q", "-L", _tunnel_cmd.c_str(),
                "-i", _ssh_id_file.c_str(),
                "-o", "StrictHostKeyChecking=no", _ssh_login.c_str(), NULL);
        }

        // if execlp returns, an error occurred (report to stderr)
        int errnum = errno;

        stderr = fdopen(stderr_pipe[1], "w");
        if (stderr == NULL) {
            fprintf(stderr, "fdopen: %s\n", strerror(errno));
            _exit(1);
        }

        fprintf(stderr, "execv: %s\n", strerror(errnum));
        fflush(stderr);
        _exit(1);
    }

    // else, I am the parent
    _log->info("ssh pid %d forked as %s", pid, _tunnel_cmd.c_str());
    _ssh_pid = pid;

    close(stdout_pipe[1]);  // close write-end of stdout
    close(stderr_pipe[1]);  // close write-end of stderr

    // make streams for convenience
    _ssh_stdout = fdopen(stdout_pipe[0], "r");
    _ssh_stderr = fdopen(stderr_pipe[0], "r");

    if ((_ssh_stdout == NULL) || (_ssh_stderr == NULL))
        return errh->error("fdopen of pipe to child: %s", strerror(errno));

    add_select(fileno(_ssh_stdout), SELECT_READ);
    add_select(fileno(_ssh_stderr), SELECT_READ);

    return 0;
}

int
SSHTunnel::signal_tunnel_process(int sig, ErrorHandler *errh)
{
    if (_ssh_pid == 0) return errh->error("ssh process already dead");

    if (kill(_ssh_pid, sig) != 0)
        return errh->error("kill(%d, %d): %s", _ssh_pid, sig, strerror(errno));
    
    _log->debug("signal %d sent to ssh pid %d", sig, _ssh_pid);
    return 0;
}

int
SSHTunnel::stop_tunnel_process(ErrorHandler *errh)
{
    if (_ssh_pid == 0)
        return errh->error("ssh tunnel not running");

    if (signal_tunnel_process(SIGTERM, errh) != 0)
        return -EINVAL;

    int status;
    int options = 0;
    pid_t rv = waitpid(_ssh_pid, &status, options);

    if (rv == 0)
        return errh->error("waitpid returned 0");

    if (rv == -1)
        return errh->error("waitpid failed for ssh pid %d: %s", _ssh_pid,
            strerror(errno));

    // make sure that waitpid's status is what we expect
    assert(WIFSIGNALED(status) || WIFEXITED(status));

    if (WIFEXITED(status)) {
        _log->info("ssh pid %d exitted normally with status %d",
            _ssh_pid, WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)) {
        if (WTERMSIG(status) == SIGTERM) {
            // ok great - this is what we expect
            _log->debug("ssh pid %d terminated by SIGTERM as expected", _ssh_pid);
        } else {
            _log->warning("ssh pid %d terminated by signal %d", _ssh_pid,
                WTERMSIG(status));
        }
    }

    _ssh_pid = 0;
    if (_ssh_stdout != NULL) {
        remove_select(fileno(_ssh_stdout), SELECT_READ);
        (void) fclose(_ssh_stdout);
    }
    if (_ssh_stderr != NULL) {
        remove_select(fileno(_ssh_stderr), SELECT_READ);
        (void) fclose(_ssh_stderr);
    }

    _log->info("ssh pid %d stopped");
    return 0;
}

String
SSHTunnel::read_handler(Element *e, void *thunk)
{
    const SSHTunnel *elt = static_cast<SSHTunnel *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_CONNECTED:
        if (elt->_ssh_pid == 0)
            return String("0");
        else
            return String("1");
    default:
        return "internal error (bad thunk value)";
    }
}

int
SSHTunnel::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    SSHTunnel* elt = static_cast<SSHTunnel*>(e);

    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
    case H_OPEN:
        return elt->start_tunnel_process(errh);
    case H_CLOSE:
        return elt->stop_tunnel_process(errh);
    default:
        return errh->error("invalid thunk");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SSHTunnel)
