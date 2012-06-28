#ifndef CLICK_POSTGRESQL_HH
#define CLICK_POSTGRESQL_HH
#include <click/element.hh>
#include <click/error.hh>
#include <click/vector.hh>
#include <libpq-fe.h>
CLICK_DECLS

/*
=c
PostgreSQL()
*/

class PostgreSQL : public Element {
public:
    PostgreSQL();
    ~PostgreSQL();

    const char *class_name() const	{ return "PostgreSQL"; }
    const char *port_count() const	{ return PORTS_0_0; }

    void *cast(const char*);
    int configure(Vector<String>&, ErrorHandler *);
    // initialize early in case other elements want to call us during their initialize()
    int configure_phase() const { return CONFIGURE_PHASE_INFO-1; }
    int initialize(ErrorHandler *);

    int db_execute(const String&, const Vector<const char*>&, ErrorHandler*);
    PGresult *db_select(const String &);

private:
    String _dbname, _dbuser, _dbpassword;
    PGconn *_dbconn;
};

CLICK_ENDDECLS
#endif
