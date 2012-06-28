/*
 * torotatingdump.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */
#include <click/config.h>
#include "torotatingdump.hh"
#include <click/confparse.hh>
#include <click/packet_anno.hh>
#include <click/router.hh>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "loghandler.hh"
CLICK_DECLS

#define SNAPLEN 2048

ToRotatingDump::ToRotatingDump()
    : _dlt(-1), _max_files(-1), _pcap(NULL), _dumper(NULL), _auto_flush(true)
{
}

ToRotatingDump::~ToRotatingDump()
{
}

int
ToRotatingDump::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String dlt_name = "EN10MB";

    if (cp_va_kparse(conf, this, errh,
            "FILENAME", cpkP+cpkM, cpFilename, &_filename,
            "DIR", 0, cpString, &_dir,
            "DLT", 0, cpString, &dlt_name,
            "MAXFILES", 0, cpInteger, &_max_files,
            "AUTOFLUSH", 0, cpBool, &_auto_flush,
            cpEnd) < 0)
	return -1;

    if ((_dir != "") && (_dir.back() != '/'))
        _dir = _dir + "/";

    _dlt = pcap_datalink_name_to_val(dlt_name.c_str());
    if (_dlt < 0)
        return errh->error("bad datalink type");

    return 0;
}

int
ToRotatingDump::initialize(ErrorHandler *errh)
{
    // create a dummy pcap handle (used only for opening dumpers)
    _pcap = pcap_open_dead(_dlt, SNAPLEN);
    if (_pcap == NULL)
        return errh->error("pcap_open_dead: %s", strerror(errno));

    // create directory if it doesn't exist
    if (_dir.length() > 0) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "mkdir -p %s", _dir.c_str());
        int rv = system(cmd);

        if (rv != 0)
            return errh->error("mkdir(%s) failed", _dir.c_str());
    }

    // find and delete any old files
    if (_max_files > 0) {
        // figure out the oldest file time that is ok
        time_t limit = time(NULL);
        struct tm tm;
        localtime_r(&limit, &tm);
        tm.tm_sec = 0;
        tm.tm_min = 0;
        tm.tm_hour = 0;
        tm.tm_mday -= _max_files;

        limit = mktime(&tm);

        DIR *dir = opendir(_dir.c_str());
        if (dir == NULL)
            return errh->error("opendir(%s): %s", _dir.c_str(), strerror(errno));

        while (1) {
            struct dirent *dirent = readdir(dir);
            if (dirent == NULL)  // hopefully dir is empty (and not error)
                break;

            const char *extension = rindex(dirent->d_name, '.');
            if (extension == NULL)
                continue;

            const char *datestr = extension+1;

            struct tm file_tm;
            bzero(&file_tm, sizeof(struct tm));

            char *unused = strptime(datestr, "%Y-%m-%d", &file_tm);
            if (unused == NULL) {
                // conversion failed - assume this is not an error and just
                // skip this file
                continue;
            }

            if (unused[0] != '\0') {
                // extra characters at the end - report error for this case
                return errh->error("failed to parse %s", dirent->d_name);
            }

            // strptime has the annoying 'feature' that it will accept partial
            // matches (e.g. "2009", "2009-10", and "2009-10-5" are all
            // acceptables matches for the format "%Y-%m-%d") whereas we really
            // just want full matches with all three fields, so we check the
            // *number* of characters that were matched since we know that it
            // must be at least 8 (the month and day fields could be either 1 or
            // 2 characters each so we don't know exactly)
            if (unused == datestr) {
                // nothing parsed at all - this is not an error
                continue;
            }

            if (unused < (datestr+8)) {
                // some parsed, but not enough
                return errh->error("truncated parsing of %s", dirent->d_name);
            }

            time_t file_time = mktime(&file_tm);

            if (file_time < limit) {
                // file is too old - kill it
                char path[1024];
                snprintf(path, sizeof(path), "%s%s", _dir.c_str(),
                    dirent->d_name);

                if (unlink(path) == 0)
                    click_chatter("deleted %s", path);
                else
                    return errh->error("unlink(%s): %s", path, strerror(errno));
            }
        }
    }

    // go ahead and try to open the first dump file now so that we can fail
    // early if an error occurs (also we can do the expensive stuff now if the
    // file already exists)
    time_t t = time(NULL);
    struct tm now;
    localtime_r(&t, &now);

    if (open_dumper(&now, errh) != 0)
        return -EINVAL;

    return 0;
}

void
ToRotatingDump::push(int, Packet *p)
{
    time_t t = time(NULL);
    struct tm now;
    localtime_r(&t, &now);

    // rotate daily
    if ((now.tm_year > _opened.tm_year) || (now.tm_mon > _opened.tm_mon) ||
        (now.tm_mday > _opened.tm_mday)) {

        // time to rotate!
        if (_dumper != NULL) pcap_dump_close(_dumper);

        StoredErrorHandler errh = StoredErrorHandler();
        if (open_dumper(&now, &errh) != 0) {
            simple_log_error(this, "%s", errh.get_last_error().c_str());
            checked_output_push(0, p);
            return;
        }

        // delete old file if there is one
        if (_max_files > 0) {
            struct tm expired = now;
            expired.tm_mday -= _max_files;

            // have to convert to raw seconds and then back to a struct tm (this
            // fixes over/underflows like "Mar -3")
            time_t t = mktime(&expired);
            localtime_r(&t, &expired);
            char path[1024];
            snprintf(path, 1024, "%s%s.%04d-%02d-%02d", _dir.c_str(),
                _filename.c_str(), expired.tm_year, expired.tm_mon,
                expired.tm_mday);

            struct stat st;
            if (stat(path, &st) == 0) {
                // file exists - kill it
                if (unlink(path) == 0)
                    click_chatter("deleted %s", path);
                else
                    simple_log_error(this, "unlink(%s): %s", path, strerror(errno));
            }
            else if (errno != ENOENT) {
                simple_log_error(this, "stat(%s): %s", path, strerror(errno));
                // just continue on, leaving this file (if it exists) alone
            }
            // else, file does not exist - we're cool
        }
    }

    struct pcap_pkthdr h;
    h.ts = p->timestamp_anno().timeval();
    h.caplen = p->length();
    h.len = p->length() + EXTRA_LENGTH_ANNO(p);

    pcap_dump((u_char*)_dumper, &h, p->data());

    if (_auto_flush) {
        if (pcap_dump_flush(_dumper) != 0)
            simple_log_error(this, "pcap_dump_flush: %s", strerror(errno));
    }

    checked_output_push(0, p);
}

int
ToRotatingDump::open_dumper(struct tm *now, ErrorHandler *errh)
{
    char path[1024];
    snprintf(path, 1024, "%s%s.%04d-%02d-%02d", _dir.c_str(),
        _filename.c_str(), now->tm_year+1900, now->tm_mon+1, now->tm_mday);

    // pcap_dump_open does not have a mechanism for appending to an existing
    // pcap file, so we have to do some funkiness to make that happen -
    // start by checking if the file even exists
    struct stat st;
    if (stat(path, &st) == 0) {
        // file exists - now, open it and scan through all of the packets to
        // make sure that the last one isn't corrupt (due to a partial write)
        FILE *fi = fopen(path, "r");
        if (fi == NULL)
            return errh->error("fopen(%s, \"r\"): %s", path, strerror(errno));

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *pcap_h = pcap_fopen_offline(fi, errbuf);
        if (pcap_h == NULL) {
            // this is probably due to a corrupt header
            errh->warning("pcap_fopen_offline(%s) failed - overwriting file (err=%s)",
                path, errbuf);
            
            // open the file the normal way, which will overwrite the existing
            // (corrupt) file
            goto normal_open;
        }

        long file_endpos = 0;

        while (1) {
            struct pcap_pkthdr *h;
            const u_char *sp;
            int rv = pcap_next_ex(pcap_h, &h, &sp);
            if (rv == 1)
                // good packet; update saved file position
                file_endpos = ftell(fi);
            else if (rv == -2) {
                // end of file; update saved file position (this is necessary
                // only when the file contains 0 packets)
                file_endpos = ftell(fi);
                break;
            }
            else {
                assert(rv == -1);  // error - bad packet
                break;
            }
        }

        fclose(fi);
        fi = fopen(path, "r+");
        if (fi == NULL)
            return errh->error("fopen(%s, \"w+\"): %s", path, strerror(errno));

        // read the file header and make sure fields look reasonable
        struct pcap_file_header pcap_header;
        if (fread(&pcap_header, sizeof(struct pcap_file_header), 1, fi) != 1)
            return errh->error("fread(%s): %s", path, strerror(errno));

        // note - should check magic number for swapped byte order

        if ((pcap_header.version_major != PCAP_VERSION_MAJOR) ||
            (pcap_header.version_minor != PCAP_VERSION_MINOR))
            return errh->error("wrong pcap header version (%d.%d): %s",
                pcap_header.version_major, pcap_header.version_minor, path);

        if (pcap_header.linktype != (uint32_t)_dlt)
            return errh->error("file dlt (%d) does not match (%d): %s",
                pcap_header.linktype, _dlt, path);

        if (fseek(fi, file_endpos, SEEK_SET) != 0)
            return errh->error("fseek(%s): %s", path, strerror(errno));

        _dumper = pcap_dump_fopen(_pcap, fi);

        // roll back the file header
        if (fseek(fi, -1*sizeof(struct pcap_file_header), SEEK_CUR) != 0)
            return errh->error("fseek[back](%s): %s", path, strerror(errno));

        if (ftruncate(fileno(fi), file_endpos) != 0)
            return errh->error("ftruncate(%s): %s", path, strerror(errno));
    }
    else if (errno != ENOENT) {
        return errh->error("stat(%s): %s", path, strerror(errno));
    }
    else {
    normal_open:
        // file does not exist - open it the normal (easy) way
        _dumper = pcap_dump_open(_pcap, path);
        if (_dumper == NULL)
            return errh->error("pcap_dump_open(%s): %s", path, pcap_geterr(_pcap));
    }

    _opened = *now;
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ToRotatingDump)
