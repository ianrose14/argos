#!/usr/bin/env python

#
# IMPORTS
#

# system modules
import datetime
import errno
import getpass
from optparse import OptionGroup, OptionParser
import os
import signal
from subprocess import (Popen, PIPE)
import sys
import tempfile
import time
import traceback

# local modules
sys.path.append("lib/python")
import argos
import argoslog
import argosroutes
import daemon


#
# METHODS
#

def db_log_filtered(entry, db_parser):
    if (entry.source != "ol_in_proxy") and (entry.source[:7] != "wifi_ol"):
        db_parser.parse_entry(entry)

# only log to disk entries of INFO level or higher
def disk_log_filtered(entry, log):
    if entry.loglevel >= argoslog.LOG_INFO:
        log.write("%s\n" % str(entry))

def isapipe(fd):
    # based on http://www.koders.com/c/fid53889FFE242B68DFAD4ADF53B788E3D05FC7BBFC.aspx?s=file:memrchr.c
    # technically this returns True for both pipes as well as FIFOs ("named
    # pipes") but that's ok for my purposes
    import stat
    s = os.fstat(fd)
    return stat.S_ISFIFO(s.st_mode)

def run(click_exe, filename, gen_pkt_src, opts, coordinator="www.citysense.net",
        citymd=False, ol_elt_params={}):
    
    logging = argos.get_logging_defaults()
    if opts.debug:
        elts = opts.debug.split(",")
        for elt in elts:
            if elt.lower() == "all":
                for key in logging:
                    logging[key] = "DEBUG"
                break
            else:
                if elt in logging:
                    logging[elt] = "DEBUG"
                else:
                    raise ValueError("no such element: %s" % elt)

    # look up nodes from testbed(s)
    argosroutes.initialize(init_routes=False)
    testbeds = {}

    if citymd:
        try:
            testbeds["citymd"] = argosroutes.get_nodes("citymd")
        except KeyError:
            raise ValueError("testbed not found: citymd")
    else:
        for tb in argosroutes.get_outdoor_testbeds():
            testbeds[tb] = argosroutes.get_nodes(tb)
    
    argos.init()
    macros = {}
    if citymd:
        macros["ARGOS_USE_CITYMD"] = None
    if opts.db is not None:
        macros["ARGOS_USE_DATABASE"] = None
    config = argos.preprocess_config(filename, macros)
    queries = argos.parse_config(config)
    
    # port that ArgosCtrlServer listens on and argosniffer connects on
    if opts.port:
        config_port = opts.port
    else:
        config_port = argos.DEF_CONFIG_PORT

    # port that NetworkProxyServer listens on (on the server) and each nodes'
    # NetworkProxy connects to
    toserver_port = config_port + 1

    # port that every node (incl. server) listens on and connects to on other
    # nodes
    overlay_port = toserver_port + 1

    # port that the server's ControlSocket element listens on
    control_port = overlay_port + 1

    args = (queries, gen_pkt_src, toserver_port, overlay_port, control_port,
            testbeds)
    kwargs = {"coordinator": coordinator, "loglvls": logging,
              "ol_elt_params": ol_elt_params}
    node_router = argos.gen_node_router(*args, **kwargs)

    (fd, filename) = tempfile.mkstemp()
    fi = os.fdopen(fd, "w")
    print >>fi, node_router
    fi.close()

    definitions = {}

    if opts.db is not None:
        db_name = opts.db
        db_user = opts.db_user
        prompt = "user '%s' on database '%s' password: " % (db_user, db_name)
        db_pass = getpass.getpass(prompt, sys.stderr)
        definitions["ARGOS_DATABASE_DBNAME"] = db_name
        definitions["ARGOS_DATABASE_USER"] = db_user
        definitions["ARGOS_DATABASE_PASSWORD"] = db_pass
    
    args = (queries, filename, toserver_port, overlay_port, control_port,
            testbeds)
    kwargs = {"coordinator": coordinator, "loglvls": logging,
              "ol_elt_params": ol_elt_params,
              "config_port": config_port, "definitions": definitions}
    server_router = argos.gen_server_router(*args, **kwargs)

    if opts.dump:
        print "#"*60
        print "#%s#" % "Node Router".center(58)
        print "#"*60
        print
        print node_router
        print
        print "#"*60
        print "#%s#" % "Server Router".center(58)
        print "#"*60
        print
        print server_router
        return
    elif opts.dump_node:
        print node_router
        return
    elif opts.dump_server:
        print server_router
        return

    argos.verify_router(node_router, "node router")
    print "~~ node router checks out ok"
    argos.verify_router(server_router, "server router")
    print "~~ server router checks out ok"

    if opts.verify:
        # done!
        return
        
    print "Running server..."
    if (opts.outdir is not None) and not os.path.exists(opts.outdir):
        os.mkdir(opts.outdir)
    
    # daemonize if requested
    if opts.daemon:
        cwd = os.getcwd()
        daemon.daemonize(pidfile=opts.pidfile)
        os.chdir(cwd)
    else:
        if opts.pidfile:
            # have to handle pidfile ourselves (instead of in daemonize())
            fi = daemon.openpidfile(opts.pidfile, ex_exist=False)
            print >>fi, "%d" % os.getpid()
            fi.close()

    # start click process
    proc = Popen("%s 2>&1" % click_exe, stdin=PIPE, stdout=PIPE, shell=True)
    proc.stdin.write(server_router)
    proc.stdin.close()

    click_sig_handler = lambda signum, frame: os.kill(proc.pid, signum)
    
    # set a signal handler to pass SIGHUP, SIGINT and SIGTERM on to click
    signal.signal(signal.SIGHUP, click_sig_handler)
    signal.signal(signal.SIGINT, click_sig_handler)
    signal.signal(signal.SIGTERM, click_sig_handler)

    closers = []
    log_handlers = []
    string_handlers = []

    # set up logging either to disk or to stdout
    if opts.outdir is None:
        if isapipe(sys.stdout.fileno()):
            # if the output of this script is a pipe, then turn off stdout buffering
            unbuffered_stdout = os.fdopen(sys.stdout.fileno(), "w", 0)
            h = lambda e: unbuffered_stdout.write("%s\n" % str(e).strip())
            log_handlers.append(("stdout", h))
            string_handlers.append(("stdout", h))
            chatter = lambda s: unbuffered_stdout.write("%s\n" % s.strip())
        else:
            h = lambda e: sys.stdout.write("%s\n" % str(e).strip())
            log_handlers.append(("stdout", h))
            string_handlers.append(("stdout", h))
            chatter = lambda s: sys.stdout.write("%s\n" % s.strip())
    else:
        import rotatinglog
        log = rotatinglog.HourlyLog(opts.outdir)
        chatter = lambda s: log.write("%s\n" % s.strip())
        h = lambda entry: disk_log_filtered(entry, log)
        log_handlers.append(("disk", h))
        string_handlers.append(("disk", chatter))
        closers.append(log.close)

    # set up database logging, if enabled
    if opts.db is not None:
        import argosdb
        db = argosdb.ArgosDB(db_user, db_pass, db_name)
        db_parser = argosdb.Parser(db)
        h = lambda entry: db_log_filtered(entry, db_parser)
        log_handlers.append(("db", h))
        close_db = lambda : db.close(commit=True)
        closers.append(close_db)

    # set up http server to display system status
    import argosstatusserver
    server = argosstatusserver.SystemStatusServer(opts.http_port)
    server.start()
    log_handlers.append(("web", server.handle_log_entry))
    closers.append(server.stop)

    # all output-handlers have been set up; now, in a loop, read and process
    # individual lines from click's output
    while 1:
        try:
            line = proc.stdout.readline()
        except IOError, e:
            if e.errno == errno.EINTR:
                continue
            else:
                raise
            
        if line == "":
            # EOF received - check if process quit
            if proc.poll() is not None:
                # yes, process is dead so we should just quit
                if proc.returncode > 128:
                    chatter("[click exitted from signal %d]" % (proc.returncode-128))
                else:
                    chatter("[click exitted with code %d]" % proc.returncode)
                break
            # else, weird - I don't think we should have gotten an EOF...
            # oh well, just ignore it
        else:
            # parse the line and pass it to each log-handler in case they want
            # it; if the line fails to parse, then pass it to the string-handlers
            # instead
            entry = argoslog.parse_line(line)
            if entry is None:
                for name, handler in string_handlers:
                    try:
                        handler(line)
                    except StandardError, e:
                        chatter("string-handler '%s' failed: %s: %s" % (name, e.__class__.__name__, str(e)))
                        chatter(traceback.format_exc())
            else:
                for name, handler in log_handlers:
                    try:
                        handler(entry)
                    except StandardError, e:
                        chatter("log-handler '%s' failed: %s: %s" % (name, e.__class__.__name__, str(e)))
                        chatter(traceback.format_exc())

    for closer in closers:
        closer()
        

#
# MAIN
#
def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    
    parser = OptionParser(usage="%prog [options] -c CONFIG [-x] CLICK-EXE")
    parser.add_option("-c", "--config", action="store", metavar="FILE",
                      help="Argos config file")
    parser.add_option("-d", "--daemon", action="store_true",
                      help="Run as daemon")
    parser.add_option("-g", "--debug", default="", metavar="ELEMENTS",
                      help="Comma-delimited list of elements to debug")
    parser.add_option("-o", "--outdir", metavar="FILE",
                      help="Write output to logs in named directory")
    parser.add_option("-P", "--pidfile", type="string", metavar="FILE",
                      help="Specify a pidfile to use.")
    parser.add_option("-p", "--port", type="int", help="Specify control port")
    parser.add_option("--citymd", action="store_true", default=False,
                      help="Run on citymd instead of the outdoor nodes")
    parser.add_option("-r", "--read", metavar="FILE",
                      help="capture from file instead of live")
    parser.add_option("-x", "--exe", metavar="BIN",
                      help="specify click executable")
    parser.add_option("--fast-routes", default=False, action="store_true",
                      help="Don't wait as long to make routing decisions")
    parser.add_option("--http-port", default=8000, type="int",
                      help="Port on which to run a web-server host system status info")
    parser.add_option("--db", default="argos", dest="db", help="database name")
    parser.add_option("--db-user", default="argos", help="database username")
    parser.add_option("--no-db", action="store_const", const=None, dest="db",
                      help="Disable all database logging")
    group = OptionGroup(parser, "Offline Options",
                        "These options apply only in conjunction with -r")
    group.add_option("--decimate", type="float", help="Drop X% of packets", metavar="X")
    group.add_option("--sync", type="float", metavar="DELAY",
                     help="Synchronize file start times")
    group.add_option("--timing", default="1", type="choice", metavar="yes|no",
                     choices=["0", "1", "yes", "no", "true", "false"],
                     help="Follow file packet spacing (default: yes)")
    parser.add_option_group(group)
    group = OptionGroup(parser, "Alternative Executions")
    group.add_option("--dump", default=False, action="store_true",
                      help="Print node and server configurations, then quit")
    group.add_option("--dump-node", default=False, action="store_true",
                      help="Print node configuration, then quit")
    group.add_option("--dump-server", default=False, action="store_true",
                      help="Print server configuration, the quit")
    group.add_option("--verify", default=False, action="store_true",
                      help="Verify syntax node and server configurations with click-check, then quit")
    parser.add_option_group(group)
    (opts, args) = parser.parse_args()

    if opts.exe is None and len(args) > 0:
        opts.exe = args.pop(0)

    if len(args) > 0:
        parser.error("too many arguments: %s" % " ".join(args))
        
    if opts.config is None:
        parser.error("no config file specified (-c)")

    # don't need to specify executable if we are just print or verifying the
    # click configurations (but not actually running anything)
    if opts.exe is None and not (opts.verify or opts.dump or opts.dump_node or opts.dump_server):
        parser.error("no click executable specified (-x or positional)")

    # allows customization of the WifiOverlay elements
    ol_elt_params={}

    if opts.fast_routes:
        ol_elt_params["ROUTES_WARMUP"] = 0
        ol_elt_params["ROUTES_MIN_DURATION"] = 15

    if opts.read is not None:
        readfile = os.path.expanduser(opts.read)

        # when reading from a file it tends to be annoying to drop packets due to
        # wait-queue overflows in the WifiOverlay element, so jack up the
        # capacities of the wait-queues
        ol_elt_params["WAITQUEUE_CAPAC"] = 1000

        # usually you want database logged disabled when reading from a file
        if opts.db is not None:
            print >>sys.stderr, \
                  "really log to database '%s' while reading from file? " % opts.db,
            s = raw_input()
            # sometimes (unclear when) the newline isn't printed from raw_input()
            print >>sys.stderr
            if s not in ["y", "Y", "1", "yes", "Yes", "YES"]:
                print "quitting"
                return
        
        if opts.sync is not None:
            sync = time.time() + opts.sync  # change from relative to absolute time
        else:
            sync = None

        if opts.decimate is not None:
            if opts.decimate < 0 or opts.decimate > 1:
                raise ValueError("--decimate cannot be <0 or >1")

        if opts.timing in ["1", "yes", "true"]:
            timing = True
        else:
            timing = False

        args = [readfile, timing, sync, opts.decimate]
        gen_pkt_src = lambda loglvls: argos.gen_offline_packet_source(loglvls, *args)
    else:
        if opts.sync is not None:
            raise ValueError("--sync option is meaningless without --read option")
        
        if opts.decimate is not None:
            raise ValueError("--decimate option is meaningless without --read option")

        gen_pkt_src = lambda loglvls: argos.gen_live_packet_source(loglvls)
        
    run(opts.exe, opts.config, gen_pkt_src, opts, citymd=opts.citymd,
        ol_elt_params=ol_elt_params)

if __name__ == '__main__':
    # import Psyco if available
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main()
