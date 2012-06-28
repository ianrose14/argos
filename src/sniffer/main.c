/*
 * Author: Ian Rose
 * Date Created: Dec 7, 2008
 *
 * "Launcher" application that connects to a server, receives a click
 * configuration back, sets a few custom variables in the click configuration,
 * and then executes it.
 */

/* system includes */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <paths.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>

/* local includes */
#include "async.h"
#include "buffer.h"
#include "argos/common.h"
#include "argos/net.h"
#include "argos/sniffer.h"
#include "orion/config.h"
#include "orion/fs.h"
#include "orion/log.h"
#include "orion/net.h"
#include "orion/string.h"
#include "orion/time.h"


/**********************/
/*  GLOBAL CONSTANTS  */
/**********************/

#define PROGNAME "argosniffer"
#define CHECK_CHILD_INTERVAL 5


/**********************/
/*  TYPE DEFINITIONS  */
/**********************/

struct child_process {
    int pid;
    struct timeval started;
    FILE *stdin;
    int stdout;
    int stderr;
    struct buffer *stdout_buf;
    struct buffer *stderr_buf;
    char pidfile[256];
};

#define EMPTY_CHILD_PROCESS { 0, {0,0}, NULL, -1, -1, NULL, NULL, "" }

struct ssh_tunnel_args {
    const char *tunnel_cmd;
    const char *ssh_login;
    const char *ssh_id_file;
};


/**********************/
/*  STATIC VARIABLES  */
/**********************/

/* network connection to the server */
static struct argos_net_conn *server_conn = NULL;

/* IP address of our wireless mesh network interface */
struct sockaddr_in mesh_ip;

/* datalinktype name */
static const char *dlt_name = ARGOS_DEF_DLTNAME;

/* if non-0, then the userid that we should drop permissions to when possible */
static uid_t uid = 0;

/* capturing interface */
static const char *if_name = ARGOS_DEF_IFNAME;

/* do not execute Click; instead, dump configuration to stdout (for debugging) */
static const char *dump_click_config = NULL;

/* where pidfiles go (default: current directory) */
static char *pidhome = ".";

/* if a signal occurred, save it here */
static volatile sig_atomic_t last_signum = 0;

/* handle to forked click process (if there is one) */
static struct child_process click_proc = EMPTY_CHILD_PROCESS;

/* handles to forked ssh tunnel processes (terminated by */
static struct child_process ssh_tunnel_proc = EMPTY_CHILD_PROCESS;

/*
 * SSH tunnel parameters - note that dummy values are required even if SSH
 * tunnelling is not enabled just so that click won't choak on the config file.
 */
static int ssh_tunnel_enabled = 0;
static const char *ssh_tunnel_login = "dummy@foo";
static const char *ssh_tunnel_id_file = "dummyfile";


/********************************/
/*  STATIC METHOD DECLARATIONS  */
/********************************/

static void become_root(void);

static void check_child_evt(void *user);

static void corefile_check(const char *filename);

static void exec_click(void *args);

static void exec_ssh_tunnel(void *args);

static const char *get_click_headers(void);

static uint32_t get_system_ram(void);

/* callback for net.c */
static void handle_connected(struct argos_net_conn *conn, void *user);

/* callback for net.c */
static void handle_disconnected(struct argos_net_conn *conn, void *user);

/* callback for net.c */
static void handle_server_error(uint16_t errnum, const char *msg, void *user);

/* callback for net.c */
static void handle_start_click(const char *router_conf, void *user);

static void init_logging(const struct orion_config_file *conf, int force_debug,
    int daemonized);

static void init_net(const struct orion_config_file *conf, int portno,
    const struct sockaddr_in *client_ip);

static void init_uid(const struct orion_config_file *conf);

static int kill_by_pid(pid_t pid);

static int kill_by_pidfile(const char * restrict pidfile);

static int lookup_address(const char *hostname, struct sockaddr_in *addr);

static void read_child_output_cb(int fd, void *user);

static int reap_child(struct child_process *proc, int nohang, int killsig);

static void release_root(void);

static void report_errno(int errnum, const char *fmt, ...);

static void setup_running_state(int daemonize);

static void signal_handler(int signum);

static int spawn_child(struct child_process *proc, const char *pidfile,
    void (*child_func)(), void *child_args);


/**********/
/*  MAIN  */
/**********/

int
main(int argc, char **argv)
{
    /* default values for command line arguments */
    const char *configfile = ARGOS_DEF_CONFIG;
    int daemonize = 0;
    int portno = 0;
    u_char force_debug = 0;

    /* process command line options */
    const char *usage =
        "usage: " PROGNAME " [-dgpv] [-c config] [-i interface] [-P pidhome] [-y datalinktype]\n";

    int c;
    while ((c = getopt(argc, argv, ":c:dghi:p:P:u:vy:")) != -1) {
        switch (c) {
        case 'c':
            configfile = optarg;
            break;
        case 'd':
            daemonize = 1;
            break;
        case 'g':
            force_debug = 1;
            break;
        case 'h':
            printf(usage);
            printf("\n"
                "options:\n"
                "    -c  specify configuration file\n"
                "    -d  daemonize\n"
                "    -g  enable debugging output\n"
                "    -h  print usage information and quit\n"
                "    -i  network interface on which to capture packets"
                " (default: %s)\n"
                "    -p  specify a server port to connect to\n"
                "    -P  write pidfiles to specified directory\n"
                "    -u  do not execute Click; instead dump config to specified file\n"
                "    -v  print version information and quit\n"
                "    -y  datalink type for capturing interface (default: %s)\n"
                "\n",
                ARGOS_DEF_IFNAME, ARGOS_DEF_DLTNAME);
            exit(0);
            break;
        case 'i':
            if_name = optarg;
            break;
        case 'p':
            portno = atoi(optarg);
            break;
        case 'P':
            pidhome = optarg;
            break;
        case 'u':
            dump_click_config = optarg;
            break;
        case 'v':
            printf("Argos network sniffer version %d.%02d  (built %s %s)\n",
                ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION, __DATE__, __TIME__);
            exit(0);
        case 'y':
            dlt_name = optarg;
            break;
        case ':':
            errx(1, "option -%c requires an operand", optopt);
            break;
        case '?':
            errx(1, "unrecognized option: -%c", optopt);
            break;
        default:
            /* unhandled option indicates programming error */
            assert(0  /* unhandled option */);
        }
    }

    if (optind != argc)
        errx(1, "program does not take arguments");

    /* set up signal handlers */
    if (signal(SIGINT, SIG_IGN) != SIG_IGN) {
        if (signal(SIGINT, signal_handler) == SIG_ERR)
            err(1, "signal(SIGINT)");
    }

    if (signal(SIGTERM, SIG_IGN) != SIG_IGN) {
        if (signal(SIGTERM, signal_handler) == SIG_ERR)
            err(1, "signal(SIGTERM)");
    }

    /* ignore SIGPIPEs (e.g. when writing router config to click process) */
    signal(SIGPIPE, SIG_IGN);

    /* handle daemonizing and/or pidfile */
    setup_running_state(daemonize);

    /*
     * Initialize various things from the configuration file.  The order that
     * these are handled is very important.  First, the username entry must be
     * handled (if present) because that will affect the owner of any files that
     * are created subsequently.  Next, logging needs to be set up so that the
     * orion_log_xxx methods actually do something.  And lastly, all other
     * parameters can be handled in any order.
     */
    struct orion_config_file *conf = orion_config_open(configfile);
    if (conf == NULL) {
        err(1, "orion_config_open(%s) at %s line %d", configfile,
            basename(__FILE__), __LINE__);
    }

    init_uid(conf);
    init_logging(conf, force_debug, daemonize);

    /* logging works at this point */
    char invocation[256] = "";
    for (int i=0; i < argc; i++) {
        strlcat(invocation, argv[i], sizeof(invocation));
        strlcat(invocation, " ", sizeof(invocation));
    }

    /*
     * start with a blank line just in case we are writing to a file that does
     * not terminate with a newline (e.g. because of a premature termination)
     */
    orion_log_raw("");
    orion_log_info(PROGNAME " starting up, version %d.%02d  (built %s %s)",
        ARGOS_MAJOR_VERSION, ARGOS_MINOR_VERSION, __DATE__, __TIME__);
    orion_log_info("invoked as %s", invocation);
    orion_log_info("config file: %s", configfile);
    orion_log_flush();

    /* lookup our wireless mesh IP address (hostname format is hard-coded) */
    char mesh_hostname[256];
    if (gethostname(mesh_hostname, sizeof(mesh_hostname)) != 0)
        err(1, "gethostname");
    strlcat(mesh_hostname, "-mgmt", sizeof(mesh_hostname));
    if (lookup_address(mesh_hostname, &mesh_ip) == -1)
        errx(1, "lookup_address");
    orion_log_info("mesh-ip: %s", inet_ntoa(mesh_ip.sin_addr));

    /*
     * Sometimes click sucks at cleaning up its SSH tunnel child processes and
     * if they are still around when we start a new click process that makes
     * things go bad.  So before (potentially) starting our own SSH tunnel
     * process in init_net(), we do a `killall ssh` just in case.  I'm not sure
     * why, but when killall fails to kill anything, the return value from
     * system(3) is 256, not 1.  <shrug>
     */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "killall -u %d ssh 2>/dev/null", geteuid());
    int rv = system(cmd);
    if ((rv != 0) && (rv != 1) && (rv != 256))
        orion_log_warn("killall ssh exited with status %d", rv);

    /* initialize network connections last */
    init_net(conf, portno, &mesh_ip);

    orion_config_close(conf);  /* done with configuration file */

    /*
     * if there is an orphaned click process running around (from a previous
     * incarnation of argosniffer that didn't clean up after itself), kill it
     */
    char pidfile[512] = "";
    strlcpy(pidfile, pidhome, sizeof(pidfile));
    strlcat(pidfile, "/click.pid", sizeof(pidfile));
    kill_by_pidfile(pidfile);

    /* kick off the async loop */
    orion_log_info("entering async loop...");
    orion_log_flush();

    rv = async_loop();
    if (rv == -1) {
        orion_log_crit_errno("async_loop");
    } else if (rv == -2) {
        orion_log_info("async_loop terminated by async_breakloop");
    } else {
        orion_log_info("async_loop terminated on its own");
    }

    /* if there is a click child process, signal it and wait on it */
    if (click_proc.pid != 0) {
        int killsig = kill_by_pid(click_proc.pid);
        if (killsig != -1)
            reap_child(&click_proc, 0 /* 0 = wait */, killsig);
    }

    /* if there is an ssh-tunnel child process, signal it and wait on it */
    if (ssh_tunnel_proc.pid != 0) {
        int killsig = kill_by_pid(ssh_tunnel_proc.pid);
        if (killsig != -1)
            reap_child(&ssh_tunnel_proc, 0 /* 0 = wait */, killsig);
    }

    orion_log_flush();
    orion_log_info("terminating packet capture");

    argos_net_close(server_conn);
    server_conn = NULL;

    /* delete argosniffer's pidfile */
    if (daemonize) {
        char pidfile[512] = "";
        strlcpy(pidfile, pidhome, sizeof(pidfile));
        strlcat(pidfile, "/" PROGNAME ".pid", sizeof(pidfile));
        if (unlink(pidfile) != 0)
            orion_log_errnof("unlink(%s)", pidfile);
    }

    orion_log_info(PROGNAME " exitting cleanly");
    orion_log_flush();

    /*
     * flush and close log to make sure everything gets written to disk; send
     * errors to warn() since the argos log isn't available (we're closing it!)
     */
    if (orion_log_close() == -1)
        warn("orion_log_close");

    return 0;
}

/********************/
/*  STATIC METHODS  */
/********************/

static void
become_root(void)
{
    if (uid != getuid()) {
        if (seteuid(0) == -1) {
            orion_log_crit_errno("seteuid(0)");
            abort();
        }
    }
}

static void
check_child_evt(void *user)
{
    struct child_process *proc = (struct child_process*)user;
    if (proc->pid == 0) return;

    if (reap_child(proc, 1 /* 1 = nohang */, last_signum) == 1) {
        /* rv of 1 means child process is still alive; reschedule check */
        if (async_schedule_sec(CHECK_CHILD_INTERVAL, check_child_evt, user, 1) == NULL)
            orion_log_errno("async_schedule()");
    } else {
        /* unexpected deaths by child processes earn us a restart */
        async_breakloop();
    }
}

static void
corefile_check(const char *filename)
{
    struct stat sb;
    if (stat(filename, &sb) == -1) {
        if (errno == ENOENT)
            ; /* file does not exist - this is fine */
        else
            /* some other (real) error */
            orion_log_errno("stat");
        return;
    }

    char cbuf[128];
    snprintf(cbuf, sizeof(cbuf), "%s exists, created at %d", filename,
        sb.st_birthtime);

    orion_log_info("%s", cbuf);

    ssize_t len = argos_net_send_errmsg(server_conn, 0, cbuf);
    if (len == -1)
        orion_log_errno("argos_net_send_errmsg");
}

static void
exec_click(void *args)
{
    (void)args;

    /* need to have root permission to access BPF devices in click program */
    become_root();

    /* otherwise quite simple! */
    execlp("./bin/click", "click", NULL);
}

static void
exec_ssh_tunnel(void *xargs)
{
    struct ssh_tunnel_args *args = (struct ssh_tunnel_args*)xargs;
    execlp("ssh", "ssh", "-N", "-a", "-x", "-q", "-L", args->tunnel_cmd,
        "-i", args->ssh_id_file, 
        "-o", "StrictHostKeyChecking=no", args->ssh_login, NULL);
}

static const char *
get_click_headers(void)
{
    /* calculate various node-specific click parameter definitions */

    uint32_t mem = get_system_ram();
    if (mem <= 10*1024*1024) {
        /* oh well - just plow onward and hope for the best */
        report_errno(0, "unreasonably small system memory detected: %u KB", mem/1024);
    }

    /*
     * First, restrict ourselves to 75% of available RAM, under the assumption
     * that there might be a few other processes running (but hopefully nothing
     * major).  Next, reserve 256 KB for IP reassembly and 10% for TCP
     * reassembly (with a minimum of 1 MB).   Finally, use 75% of the available
     * memory as the click router's low memory limit (and 100% as the high
     * memory limit).
     */
    int32_t avail_mem = 3*(mem/4);
    int32_t ip_mem = 256*1024;
    int32_t tcp_mem = avail_mem/10;
    if (tcp_mem < 1024*1024)
        tcp_mem = 1024*1024;

    orion_log_info("%d KB of user memory detected", mem/1024);

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0)
        err(1, "gethostname");

    /* first write local variable definitions */
    const char *param_format =
        "define($ARGOS_HOSTNAME %s);\n"
        "define($ARGOS_OVERLAY_IP %s);\n"
        "define($ARGOS_DEVNAME %s);\n"
        "define($ARGOS_DATALINKTYPE %s);\n"
        "define($ARGOS_MEM_LOW_LIMIT %d);\n"
        "define($ARGOS_MEM_HIGH_LIMIT %d);\n"
        "define($ARGOS_IP_REASS_HIMEM %d);\n"
        "define($ARGOS_SSH_TUNNEL %d);\n"
        "define($ARGOS_SSH_LOGIN %s);\n"
        "define($ARGOS_SSH_ID_FILE %s);\n";

    char *params = NULL;
    int rv = asprintf(&params, param_format, hostname, inet_ntoa(mesh_ip.sin_addr),
        if_name, dlt_name, 3*(avail_mem/4), avail_mem, ip_mem, ssh_tunnel_enabled,
        ssh_tunnel_login, ssh_tunnel_id_file);

    if (rv == -1) {
        report_errno(errno, "asprintf in %s", __func__);
        return NULL;
    }

    return params;
}

static uint32_t
get_system_ram(void)
{
    /* used in the event of a lookup failure */
#define DEFAULT_RAM (64*1024*1024)  /* 64 MB */

    /*
     * look up user memory available on this machine; note that this is simply
     * [physical memory] - [currently wired memory] and thus does not take into
     * account any currently running programs.
     * reference: http://www.cyberciti.biz/files/scripts/freebsd-memory.pl.txt
     */
    FILE *sysctl_out = popen("sysctl -n hw.usermem", "r");
    if (sysctl_out == NULL) {
        report_errno(errno, "sysctl -n hw.usermem");
        return DEFAULT_RAM;
    }

    uint32_t user_mem = 0;
    int val = fscanf(sysctl_out, "%u\n", &user_mem);
    int rv = pclose(sysctl_out);
    if (rv != 0) {
        report_errno(0, "sysctl -n hw.usermem exitted with code %d", rv);
        return DEFAULT_RAM;  /* do not trust any value parsed from sysctl output */
    }

    if (val != 1) {
        report_errno(0, "failed to parse output of `sysctl -n hw.usermem`");
        return DEFAULT_RAM;
    }

    return user_mem;
#undef DEFAULT_RAM
}

static void
handle_connected(struct argos_net_conn *conn, void *user)
{
    (void) conn;  /* unused */
    (void) user;  /* unused */

    /*
     * check for a corefile from a previous execution, and send an error
     * message to the server if one is found (DISABLED FOR NOW)
     */
#if 0
    corefile_check(PROGNAME ".core");
    corefile_check("click.core");
#endif
}

static void
handle_disconnected(struct argos_net_conn *conn, void *user)
{
    /*
     * Currently we don't really care about disconnected operation and allowing
     * existing click processes to connect to a freshly started click server can
     * be a bit annoying (the code doesn't seem to handle that as gracefully as
     * I'd like) so we might as well just kill click whenever argosniffer is
     * disconnected (and restart it, as normal, once argosniffer is able to
     * reconnect to the server).  However, SSH tunnel process *are not* killed
     * here; they are spawned at startup time (if at all) and not killed until
     * this process quits.
     */
    if (click_proc.pid != 0) {
        pid_t p = click_proc.pid;
        int killsig = kill_by_pid(click_proc.pid);
        if (killsig == -1)
            err(1, "kill");  /* I fail to see the humor in kill(2) failures */

        reap_child(&click_proc, 0 /* 0 = wait */, killsig);
        orion_log_info("click child %d killed due to disconnection from server", p);
    }

    (void)conn;
    (void)user;
}

static void
handle_server_error(uint16_t errnum, const char *msg, void *user)
{
    orion_log_err("[server] %s (%s)", strerror(errnum), msg);
    orion_log_flush();

    // for any errno but 0, we restart completely
    if (errnum != 0) async_breakloop();
}

static void
handle_start_click(const char *router_conf, void *user)
{
    (void) user;  /* unused */

    const char *click_headers = get_click_headers();
    if (click_headers == NULL) {
        orion_log_err("start-click operation failed");
        orion_log_flush();
        return;
    }

    if (dump_click_config != NULL) {
        FILE *fi = fopen(dump_click_config, "w");
        if (fi == NULL) {
            orion_log_err("fopen(%s): %s", dump_click_config, strerror(errno));
            return;
        }
        fprintf(fi, "%s\n", click_headers);
        fprintf(fi, "%s\n", router_conf);
        if (ferror(fi))
            orion_log_err("fprintf(%s) failed", dump_click_config);
        if (fclose(fi) != 0)
            orion_log_err("fclose(%s): %s", dump_click_config, strerror(errno));
        else
            orion_log_info("click config written to %s", dump_click_config);
        return;
    }

    /* if we already have a click child running, kill it */
    if (click_proc.pid != 0) {
        int killsig = kill_by_pid(click_proc.pid);
        if (killsig == -1)
            return;

        orion_log_info("seemed to have killed an orphaned click process...");
        reap_child(&click_proc, 0 /* 0 = wait */, killsig);
    }

    char pidfile[512];
    strlcpy(pidfile, pidhome, sizeof(pidfile));
    strlcat(pidfile, "/click.pid", sizeof(pidfile));
    (void) kill_by_pidfile(pidfile); 

    if (spawn_child(&click_proc, pidfile, exec_click, NULL) != 0)
        errx(1, "spawn_child failed to launch click process");

    orion_log_info("click process forked (pid=%d)", click_proc.pid);

    /*
     * Now we just need to write the configuration that we got from the server
     * to the click process, prepended by some node-specific click parameter
     * definitions.
     */
    int rv = fprintf(click_proc.stdin, "%s\n", click_headers);
    if (rv == -1) {
        report_errno(0, "fprintf to child failed: %s", strerror(errno));
        return;
    }

    rv = fprintf(click_proc.stdin, "%s\n", router_conf);
    if (rv == -1) {
        report_errno(0, "fprintf to child failed: %s", strerror(errno));
        return;
    }

    /* done writing router config to child process */
    fclose(click_proc.stdin);
    orion_log_debug("successfully wrote complete router config to child"
        " process (%d bytes)", strlen(router_conf));
}

/* set up logging from configuration file settings */
static void
init_logging(const struct orion_config_file *conf, int force_debug, int daemonized)
{
    /* force_debug_logging variable can override config file setting */
    if (force_debug) {
        orion_log_set_level(ORION_LOG_DEBUG);
    } else {
        /* loglevel */
        const char *loglevel = orion_config_get_str(conf, "loglevel", NULL);
        if (loglevel != NULL) {
            enum orion_log_level lvl = orion_log_lookup_level(loglevel);
            if (lvl == -1)
                errx(1, "invalid loglevel parameter value: \"%s\"", loglevel);
            orion_log_set_level(lvl);
        }
    }

    /* open argos log (destination depends on whether we daemonized) */
    if (daemonized) {
        /* logname */
        const char *raw_logname = orion_config_get_str(conf, "logname",
            ARGOS_DEF_LOGNAME);

        /* logdir */
        const char *raw_logdir = orion_config_get_str(conf, "logdir",
            ARGOS_DEF_LOGDIR);

        /*
         * pass each variable through a shell (e.g. to resolve environment
         * variables)
         */
        char logname[ARGOS_MAX_PATH_LEN+1];
        char logdir[ARGOS_MAX_PATH_LEN+1];

        ssize_t rv = orion_str_unshellify(raw_logname, logname, sizeof(logname));
        if (rv == -1) err(1, "invalid 'logname' configuration entry");

        rv = orion_str_unshellify(raw_logdir, logdir, sizeof(logdir));
        if (rv == -1) err(1, "invalid 'logdir' configuration entry");

        if (orion_log_open(logdir, logname) == -1)
            err(1, "orion_log_open at %s line %d", basename(__FILE__), __LINE__);
    } else {
        if (setlinebuf(stdout) != 0)
            err(1, "setlinebuf at %s line %d", basename(__FILE__), __LINE__);

        if (orion_log_fopen(stdout) == -1)
            err(1, "orion_log_fopen at %s line %d", basename(__FILE__), __LINE__);
    }
}

/* create a network connection according to configuration file settings */
static void
init_net(const struct orion_config_file *conf, int portno,
    const struct sockaddr_in *client_ip)
{
    const char *server_hostname = orion_config_get_str(conf, "server_hostname",
        ARGOS_NET_DEF_SERVER_HOSTNAME);

    char my_hostname[256];
    if (gethostname(my_hostname, sizeof(my_hostname)) != 0)
        err(1, "gethostname");

    if (portno == 0)
        portno = orion_config_get_int(conf, "server_port",
            ARGOS_NET_DEF_SERVER_PORT);

    orion_log_info("server: %s:%d", server_hostname, portno);

    /* check if we are one of the hosts have to use an SSH tunnel */
    for (int i=0; ; i++) {
        char key[128];
        snprintf(key, sizeof(key), "tunnel_host_%d", i);
        const char *tun_hostname = orion_config_get_str(conf, key, NULL);
        if (tun_hostname == NULL) break;

        if (strcmp(tun_hostname, my_hostname) == 0) {
            /* found myself in the list! */
            ssh_tunnel_enabled = 1;
            break;
        }
    }

    struct sockaddr_in sin;
    if (ssh_tunnel_enabled) {
        if (orion_net_lookup_inaddr("localhost", portno, SOCK_STREAM, &sin) == -1)
            err(1, "orion_net_lookup_inaddr");

        const char *str = orion_config_get_str(conf, "ssh_login", NULL);
        if (str == NULL)
            errx(1, "no ssh_login parameter (required for SSH tunnelling)");
        ssh_tunnel_login = strdup(str);

        char tunnel_cmd[1024];
        snprintf(tunnel_cmd, sizeof(tunnel_cmd), "localhost:%d:%s:%d", portno,
            server_hostname, portno);

        str = orion_config_get_str(conf, "ssh_id_file", NULL);
        if (str == NULL)
            errx(1, "no ssh_id_file parameter (required for SSH tunnelling)");
        ssh_tunnel_id_file = strdup(str);

        struct ssh_tunnel_args args;
        args.tunnel_cmd = tunnel_cmd;
        args.ssh_login = ssh_tunnel_login;
        args.ssh_id_file = ssh_tunnel_id_file;

        char pidfile[512];
        strlcpy(pidfile, pidhome, sizeof(pidfile));
        strlcat(pidfile, "/ssh_tunnel.pid", sizeof(pidfile));
        kill_by_pidfile(pidfile);

        orion_log_info("ssh tunneling via %s", tunnel_cmd);

        if (spawn_child(&ssh_tunnel_proc, pidfile, exec_ssh_tunnel, &args) != 0)
            errx(1, "spawn_child failed to launch ssh tunnel process");

        orion_log_info("ssh tunnel process forked (pid=%d)", ssh_tunnel_proc.pid);
    }
    else {
        if (orion_net_lookup_inaddr(server_hostname, portno, SOCK_STREAM, &sin) == -1)
            err(1, "orion_net_lookup_inaddr");
    }

    /* have to initialize network component before creating connection object */
    if (argos_net_init() != 0)
        err(1, "argos_net_init");

    int inbufsz = orion_config_get_int(conf, "net_inbuf_kb", ARGOS_DEF_NET_INBUF_KB);
    int outbufsz = orion_config_get_int(conf, "net_outbuf_kb", ARGOS_DEF_NET_OUTBUF_KB);
    int pktbufsz = orion_config_get_int(conf, "net_pktbuf_kb", ARGOS_DEF_NET_PKTBUF_KB);

    /* the server doesn't care what DLT value we specify, so just sent 0 */
    int dlt = 0;
    
    server_conn = argos_net_client_create(&sin, dlt, client_ip, inbufsz*1024,
        outbufsz*102, pktbufsz*1024);
    if (server_conn == NULL)
        err(1, "argos_net_client_create");

    orion_log_debug("network buffers (KB):  inbuf=%d outbuf=%d pktbuf=%d",
        inbufsz, outbufsz, pktbufsz);

    argos_net_set_breakhandler(server_conn, handle_disconnected, NULL);
    argos_net_set_clickhandler(server_conn, handle_start_click, NULL);
    argos_net_set_connecthandler(server_conn, handle_connected, NULL);
    argos_net_set_errhandler(server_conn, handle_server_error, NULL);
}

/* initialize uid variable by looking up username from config file */
static void
init_uid(const struct orion_config_file *conf)
{
    const char *username = orion_config_get_str(conf, "username", NULL);
    if (username == NULL) return;
    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL)
        errx(1, "getpwname: unknown user: \"%s\"", username);
    uid = pwd->pw_uid;

    if (uid == getuid()) return;

    /*
     * this is a bit of a hack; need to make sure the system supports coredumps
     * from processes that change user credentials
     */
    /* DISABLED FOR NOW */
#if 0
    int rv = system("sysctl kern.sugid_coredump=1 >/dev/null");

    if (rv == -1)
        err(1, "system at %s line %d", basename(__FILE__), __LINE__);
    else if (rv == 127)
        errx(1, "system at %s line %d: shell execution failed",
            basename(__FILE__), __LINE__);
    else if (rv != 0)
        errx(1, "sysctl at %s line %d: failed", basename(__FILE__), __LINE__);
#endif

    /* change to specified user id immediately */
    if (seteuid(uid) == -1)
        err(1, "seteuid at %s line %d", basename(__FILE__), __LINE__);
}

/* if successful, returns the signal used to kill the process; else returns -1 */
static int
kill_by_pid(pid_t pid)
{
    orion_log_debug("attempting to kill pid %d (if it exists)", pid);

    if (kill(pid, SIGTERM) == -1) {
        /* ESRCH is fine; just means the process isn't running */
        if (errno == ESRCH)
            return 0;  /* process was not killed by me, so return 0 */
        orion_log_errnof("kill(%d, SIGTERM)", pid);
        return -1;
    }

    /* else, kill succeeded, so process must exist! */
    sleep(10);  /* give the process 10s to quit cleanly */

    if (kill(pid, SIGKILL) == -1) {
        /* go nuclear in case its still alive */
        if (errno == ESRCH)
            return SIGTERM;  /* process must have been kill by my SIGTERM above */
        orion_log_errnof("kill(%d, SIGKILL)", pid);
        return -1;
    }

    return SIGKILL;  /* trust that the SIGKILL will successfully kill it */
}

/* if successful, returns the signal used to kill the process; else returns -1 */
static int
kill_by_pidfile(const char * restrict pidfile)
{
    FILE *fi = fopen(pidfile, "r");
    if (fi == NULL) {
        /* ENOENT is fine; the pidfile does not have to exist */
        if (errno == ENOENT)
            return 0;
        orion_log_errnof("failed to open \"%s\"", pidfile);
        return -1;
    }

    char buf[32];
    buf[0] = '\0';

    if (fgets(buf, sizeof(buf), fi) == NULL) {
        if (ferror(fi))
            orion_log_errnof("failed to read from \"%s\"", pidfile);
        /* else, EOF, which is fine (pidfile is allowed to be empty) */
    }

    fclose(fi);
    if (strlen(buf) == 0)
        return 0;

    char *end = NULL;
    int pid = (int)strtol(buf, &end, 10);

    if (end[0] == '\n') end[0] = '\0';

    /* something wonky with string (warn, but continue anyways) */
    if (end[0] != '\0')
        orion_log_warn("contents of click pidfile not clean: %s", buf);

    if (pid != 0)
        return kill_by_pid(pid);

    orion_log_warn("invalid click pidfile contents (parsed '0')");
    return -1;
}

static int
lookup_address(const char *hostname, struct sockaddr_in *addr)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int rv = getaddrinfo(hostname, NULL, &hints, &servinfo);
    if (rv != 0) {
        orion_log_err("getaddrinfo(%s): %s", hostname, gai_strerror(rv));
        return -1;
    }

    // if getaddrinfo returns 0, it should return a list of addrinfo structs, of
    // which we just take whichever entry happens to be first
    assert(servinfo != NULL);
    assert(servinfo->ai_addrlen <= sizeof(struct sockaddr_in));

    memcpy(addr, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);
    return 0;
}

static void
read_child_output_cb(int fd, void *user)
{
    struct child_process *proc = (struct child_process*)user;

    /*
     * just read and echo output from child's stdout; for child's stderr, do the
     * same but also send each line as an error message to the server
     */
    struct buffer *buf;
    char *fd_name;
    if (fd == proc->stdout) {
        buf = proc->stdout_buf;
        fd_name = "stdout";
    }
    else if (fd == proc->stderr) {
        buf = proc->stderr_buf;
        fd_name = "stderr";
    }
    else {
        orion_log_err("invalid fd argument to read_child_output_cb: %d", fd);
        async_remove_fd(fd);
        return;
    }

    ssize_t len = read(fd, buffer_tail(buf), buffer_remaining(buf));
    if (len == -1) {
        if (errno != EINTR) {
            orion_log_errnof("read from child %s's %s", proc->pid, fd_name);
            async_remove_fd(fd);
            /* unexpected I/O errors earn us a restart */
            async_breakloop();
        }
        return;
    }
    else if (len == 0) {
        /*
         * EOF - just stop selecting this fd (we assume process will probably
         * quit on its own soon which check_child_evt() will notice and handle)
         */
        async_remove_fd(fd);
    }
    else {
        /* some data read from fd into the buffer */
        if (buffer_expand(buf, len) == -1) {
            orion_log_err("buffer_expand failed at line %d.  buflen=%d, read-len=%d",
                __LINE__, buffer_len(buf), len);
            async_breakloop();
            return;
        }

        /* parse out complete lines */
    parse_line:
        for (int i=0; i < buffer_len(buf); i++) {
            u_char *arr = buffer_head(buf);
            if (arr[i] == '\n') {
                orion_log_raw("%.*s", i+1, arr);

                if (fd == proc->stderr) {
                    /* truncate the trailing newline */
                    arr[i] = '\0';
                    ssize_t len = argos_net_send_errmsg(server_conn, 0, (char*)arr);
                    if (len == -1)
                        orion_log_errno("argos_net_send_errmsg");
                }

                if (buffer_discard(buf, i+1) == -1) {
                    orion_log_err("buffer_discard failed at line %d.  buflen=%d, i=%d",
                        __LINE__, buffer_len(buf), i);
                    async_breakloop();
                    return;
                }

                /* see if there is another line to parse out */
                goto parse_line;
            }
        }
    }
}

static int
reap_child(struct child_process *proc, int nohang, int killsig)
{
    assert(proc->pid != 0);

    struct rusage rusage;
    int status = 0;
    int flags = nohang ? WNOHANG : 0;
    pid_t rv = wait4(proc->pid, &status, flags, &rusage);

    if (rv == -1) {
        /*
         * we quit if an error occurs because this function is supposed to
         * return only if the child process has been exitted
         */
        orion_log_crit_errno("waitpid");
        err(1, "waitpid");
    } else if (rv == 0) {
        return 1;  /* 1 = process is alive */
    }

    /* else, process is dead and rv holds its pid */
    assert(rv == proc->pid);

    /* make sure that waitpid's status is what we expect */
    assert(WIFSIGNALED(status) || WIFEXITED(status));

    /* calculate approximate %cpu used (user+system) */
    struct timeval now;
    gettimeofday(&now, NULL);

    double elapsed_sec = (now.tv_sec - proc->started.tv_sec) +
        (now.tv_usec - proc->started.tv_usec)/(double)1000000;
    double cpu_sec = (rusage.ru_utime.tv_sec + rusage.ru_stime.tv_sec) +
        (rusage.ru_utime.tv_usec + rusage.ru_stime.tv_usec)/(double)1000000;

    char resources[512];
    snprintf(resources, sizeof(resources), "time: %.1fs, %%cpu: %.3f, maxrss: %ld KB",
        elapsed_sec, cpu_sec/elapsed_sec, rusage.ru_maxrss);

    if (WIFEXITED(status)) {
        if (nohang) {
            /* if nohang, any click exit is unexpected */
            report_errno(0, "child %d exitted with status %d (%s)",
                rv, WEXITSTATUS(status), resources);
        } else {
            /* if 'hang', then click exit 0 is expected */
            if (WEXITSTATUS(status) == 0)
                orion_log_info("child %d exitted with status 0 (%s)",
                    rv, resources);
            else
                report_errno(0, "child %d exitted with status %d (%s)",
                    rv, WEXITSTATUS(status), resources);
        }
    }
    else if (WIFSIGNALED(status)) {
        if ((WTERMSIG(status) == killsig) || (WTERMSIG(status) == last_signum)) {
            orion_log_info("child %d killed by signal %d as expected (%s)",
                rv, WTERMSIG(status), resources);
        } else {
            report_errno(0, "child %d killed by signal %d (%s)",
                rv, WTERMSIG(status), resources);
        }
    }

    /* delete child's pidfile, if it has one */
    if (strlen(proc->pidfile) > 0) {
        if (unlink(proc->pidfile) != 0)
            orion_log_errnof("unlink(%s)", proc->pidfile);
    }

    async_remove_fd(proc->stdout);
    async_remove_fd(proc->stderr);

    // IMPORTANT: set PID to 0 to mark that this process is no longer running
    proc->pid = 0;

    return 0;  /* 0 = process is dead */
}

static void
release_root(void)
{
    if (uid != 0) {
        if (seteuid(uid) == -1) {
            orion_log_crit_errnof("seteuid(%d)", uid);
            abort();
        }
    }
}

static void
report_errno(int errnum, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    char cbuf[10240];
    int len = vsnprintf(cbuf, sizeof(cbuf), fmt, ap);
    if (errnum)
        snprintf(cbuf + len, sizeof(cbuf) - len, " failed: %s",
            strerror(errnum));
    va_end(ap);

    orion_log_err("%s", cbuf);
    ssize_t l = argos_net_send_errmsg(server_conn, errnum, cbuf);
    if (l == -1)
        orion_log_errno("argos_net_send_errmsg");
}

static void
setup_running_state(int daemonize)
{
    if (!daemonize) return;

    char pidfile[512] = "";
    strlcpy(pidfile, pidhome, sizeof(pidfile));
    strlcat(pidfile, "/" PROGNAME ".pid", sizeof(pidfile));

    int pidfd = orion_fs_open_pidfile(pidfile);
    if (pidfd == -1) {
        /* I have no idea why, but err(3) is printing the wrong error message */
        errx(1, "orion_fs_open_pidfile at %s line %d: %s",
            basename(__FILE__), __LINE__, strerror(errno));
    } else if (pidfd == -2) {
        /* according to pidfile, process is already running */
        errx(1, "process already running");
    }

    FILE *pidhandle = fdopen(pidfd, "w");
    if (pidhandle == NULL)
        err(1, "fdopen at %s line %d", basename(__FILE__), __LINE__);

    int fd = open(_PATH_DEVNULL, O_RDWR, 0);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    /* keep stderr if possible (i.e. its not a tty) */
    if (isatty(STDERR_FILENO)) dup2(fd, STDERR_FILENO);
    close(fd);

    if (daemon(1 /* don't chdir */, 1 /* don't redirect fds */) == -1)
        err(1, "daemon at %s line %d", basename(__FILE__), __LINE__);

    /* now that we have our final pid, write it to the pidfile */
    if (fprintf(pidhandle, "%d\n", getpid()) < 0)
        err(1, "fprintf to pidfile");
    if (fclose(pidhandle) < 0)
        err(1, "fclose on pidfile");
}

/*
 * this method's contents are modelled on:
 * http://www.cs.utah.edu/dept/old/texinfo/glibc-manual-0.02/library_21.html#SEC353 
 */
static volatile sig_atomic_t quit_requests = 0;

static void
signal_handler(int signum)
{
    last_signum = signum;

    if ((signum != SIGINT) && (signum != SIGTERM)) {
        /* bad signal received */
        assert(0  /* invalid signal */);
    }

    quit_requests++;

    if (signal(signum, SIG_DFL) == SIG_ERR)
        _Exit(EXIT_FAILURE);

    if (quit_requests > 1) {
        if (raise(signum) != 0)
            /* better to use _Exit(3) or _exit(2)?  not sure */
            _Exit(EXIT_FAILURE);
    }

    /*
     * helps for debugging - we use stderr instead of writing to the log because
     * the log might come out weird if we did (e.g. if the signal occurred
     * half-way through printing a sentence to the log then the resulting text
     * will be a little mixed up).
     */
    time_t now = time(NULL);
    char timestamp[32];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0';

    fprintf(stderr, "%s   caught signal %d\n", timestamp, signum);
    fflush(stderr);

    /*
     * Break out of async_loop().  Note that if we are in the middle of
     * a call to pcap_dispatch() it might take a while before
     * async_loop() actually terminates.
     *
     * Note that async_breakloop() just sets a flag and thus is safe to
     * call from inside a signal handler.
     */
    async_breakloop();
}

static int
spawn_child(struct child_process *proc, const char *pidfile, void (*child_func)(),
    void *child_args)
{
    int pidfd = 0;
    if (pidfile != NULL) {
        pidfd = orion_fs_open_pidfile(pidfile);
        if (pidfd == -1) {
            /* some kind of error opening, reading or deleting the pidfile */
            report_errno(errno, "orion_fs_open_pidfile(%s)", pidfile);
            return -1;
        }
        else if (pidfd == -2) {
            /*
             * -2 indicates that the process is already running; we assume that
             * the caller has taken precautions to ensure this shouldn't happen.
             */
            report_errno(0, "orion_fs_open_pidfile(%s) returned -2", pidfile);
            return -1;
        }
    }

    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];
    if ((pipe(stdin_pipe) != 0) || (pipe(stdout_pipe) != 0) ||
        (pipe(stderr_pipe) != 0)) {
        report_errno(errno, "pipe");
        return -1;
    }

    int pid = fork();
    if (pid == -1) {
        report_errno(errno, "fork");
        return -1;
    }

    if (pid == 0) {
        /* I am the child - copy pipes onto standard streams, then exec */
        if (pidfd != 0) close(pidfd);

        close(stdin_pipe[1]);   /* close write-end of stdin */
        close(stdout_pipe[0]);  /* close read-end of stdout */
        close(stderr_pipe[0]);  /* close read-end of stderr */

        dup2(stdin_pipe[0], STDIN_FILENO);    /* copy read-end of stdin */
        dup2(stdout_pipe[1], STDOUT_FILENO);  /* copy write-end of stdout */
        dup2(stderr_pipe[1], STDERR_FILENO);  /* copy write-end of stderr */

        /* this should call something from the exec() family and not return */
        child_func(child_args);

        /* if the child func returns, an error occurred (report to stderr) */
        int errnum = errno;

        /* we may or may not be root; release it just in case we are */
        release_root();

        stderr = fdopen(stderr_pipe[1], "w");
        if (stderr == NULL) {
            fprintf(stderr, "fdopen: %s\n", strerror(errno));
            _exit(1);
        }

        fprintf(stderr, "exec*: %s\n", strerror(errnum));
        fflush(stderr);
        _exit(1);
    }

    /* 
     * else, I am the parent - write and close pidfile, then save and return a
     * handle to the child process
     */

    /* pidfile error handling is kinda shoddy - we mostly just give up */
    if (pidfd != 0) {
        FILE *pidhandle = fdopen(pidfd, "w");
        if (pidhandle == NULL) {
            report_errno(errno, "fdopen at %s line %d", basename(__FILE__),
                __LINE__);
            return -1;
        }

        if (fprintf(pidhandle, "%d\n", pid) < 0)
            report_errno(errno, "fprintf at %s line %d", basename(__FILE__),
                __LINE__);
        if (fclose(pidhandle) < 0)
            report_errno(errno, "fclose at %s line %d", basename(__FILE__),
                __LINE__);
    }

    /* save child process info */
    proc->pid = pid;
    gettimeofday(&proc->started, NULL);
    proc->stdin = fdopen(stdin_pipe[1], "w");
    proc->stdout = stdout_pipe[0];
    proc->stderr = stderr_pipe[0];
    proc->stdout_buf = buffer_create(8192);
    proc->stderr_buf = buffer_create(8192);

    if (pidfd == 0)
        proc->pidfile[0] = '\0';
    else
        snprintf(proc->pidfile, sizeof(proc->pidfile), pidfile);

    close(stdin_pipe[0]);   /* close read-end of stdin */
    close(stdout_pipe[1]);  /* close write-end of stdout */
    close(stderr_pipe[1]);  /* close write-end of stderr */

    if (proc->stdin == NULL) {
        report_errno(errno, "fdopen of child's stdin");
        return -1;
    }

    /* periodically check to see if child has died */
    if (async_schedule_sec(1, check_child_evt, proc, 1) == NULL)
        orion_log_errno("async_schedule()");

    /* also read and process any output that it produces */
    int rv = async_add_read_fd(proc->stdout, ARGOS_CHILD_READ_ASYNCPRIO,
        async_true_check, read_child_output_cb, proc);
    assert(rv == 0);

    rv = async_add_read_fd(proc->stderr, ARGOS_CHILD_READ_ASYNCPRIO,
        async_true_check, read_child_output_cb, proc);
    assert(rv == 0);

    return 0;
}
