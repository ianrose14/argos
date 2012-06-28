#ifndef CLICK_SSHTUNNEL_HH
#define CLICK_SSHTUNNEL_HH
#include <click/element.hh>
#include "loghandler.hh"
CLICK_DECLS

/*
=c
SSHTunnel()

=s Argos

*/

class SSHTunnel : public Element {
public:
    SSHTunnel();
    ~SSHTunnel();

    const char *class_name() const	{ return "SSHTunnel"; }
    const char *port_count() const	{ return PORTS_0_0; }

    void add_handlers();
    void cleanup(CleanupStage);
    int configure(Vector<String>&, ErrorHandler*);
    int initialize(ErrorHandler*);
    void selected(int);

private:
    void check_tunnel_process();
    int start_tunnel_process(ErrorHandler *);
    int signal_tunnel_process(int, ErrorHandler *);
    int stop_tunnel_process(ErrorHandler *);
    static String read_handler(Element*, void *);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    String _tunnel_cmd, _ssh_id_file, _ssh_login;
    pid_t _ssh_pid;
    FILE *_ssh_stdout, *_ssh_stderr;
    int _sudo_uid;
    Logger *_log;
};

CLICK_ENDDECLS
#endif
