/*
 * postgresql.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "postgresql.hh"
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS


PostgreSQL::PostgreSQL() : _dbconn(NULL)
{
}

PostgreSQL::~PostgreSQL()
{
    if (_dbconn != NULL) PQfinish(_dbconn);
}

void *
PostgreSQL::cast(const char *n)
{
    if (strcmp(n, "PostgreSQL") == 0)
        return (PostgreSQL*)this;
    else
        return 0;
}

int
PostgreSQL::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh,
            "DATABASE", cpkP+cpkM, cpString, &_dbname,
            "USER", cpkP+cpkM, cpString, &_dbuser,
            "PASSWORD", cpkP+cpkM, cpString, &_dbpassword,
            cpEnd) < 0)
        return -1;

    return 0;
}

int
PostgreSQL::initialize(ErrorHandler *errh)
{
    String connstr = "dbname=" + _dbname + " user=" + _dbuser +
        " password=" + _dbpassword;

    _dbconn = PQconnectdb(connstr.c_str());
    if (PQstatus(_dbconn) != CONNECTION_OK) {
        errh->error("failed to connected to database: %s", PQerrorMessage(_dbconn));
        PQfinish(_dbconn);
        _dbconn = NULL;
        return -1;
    }

    return 0;
}

int
PostgreSQL::db_execute(const String &query, const Vector<const char*> &args,
    ErrorHandler *errh)
{
    int nParams = args.size();

    // we need to pass a variable-length array for the paramValues argument of
    // PQexecParams; rather than allocate and free it dynamically each time this
    // method is called, we just allocate a fixed-length array on the stack and
    // assume that it'll be big enough for any situation
    const char *paramValues[1024];

    if (nParams > 1024)
        return errh->error("too many arguments specified (%d)", nParams);

    for (int i=0; i < nParams; i++)
        paramValues[i] = args[i];

    PGresult *result = PQexecParams(_dbconn, query.c_str(),
        nParams,
        NULL, /* paramTypes (can be NULL to make server infer data types) */
        paramValues,
        NULL,  /* paramLengths (can by NULL if there are no binary parameters) */
        NULL,  /* paramFormats (NULL means "all parameters assumed to be text" */
        0); /* resultFormat (0 = obtain results in text format) */

    if (result == NULL)
        return errh->error("command failed: NULL returned");

    char *s = PQcmdTuples(result);
    int rows = (int)strtol(s, NULL, 10);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        // postgres likes to return multiline errors, so single-line-ify them
        // (this makes the formatting ugly, but ErrorHandlers expect single-line
        // arguments so we gotta do it)
        char *pq_err = PQerrorMessage(_dbconn);
        if (pq_err == NULL) {
            errh->error("command failed: [no error message]");
        }
        else {
            char *errmsg = strdup(pq_err);
            for (char *cptr = errmsg; *cptr != '\0'; cptr++) {
                if (*cptr == '\n')
                    *cptr = ' ';
            }
            errh->error("command failed: %s", errmsg);
            free(errmsg);
        }

        PQclear(result);

        // check the status of the connection (some command failures are due to
        // connection failures, in which case we may need to reconnect)
        if (PQstatus(_dbconn) != CONNECTION_OK)
            PQreset(_dbconn);

        return -1;
    }

    PQclear(result);
    return rows;
}

PGresult*
PostgreSQL::db_select(const String &query)
{
    return PQexec(_dbconn, query.c_str());
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(PostgreSQL)
ELEMENT_LIBS(-L/usr/local/lib/ -lpq)
