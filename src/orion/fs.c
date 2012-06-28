/*
 * Author: Ian Rose
 * Date Created: Jan 22, 2009
 *
 * Filesystem-related utility functions.
 */

/* system includes */
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>    /* for dirname() */
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

/* local includes */
#include "orion/fs.h"


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

/*
 * recursively create a directory and any necessary parent directories; based on
 * http://nion.modprobe.de/blog/archives/357-Recursive-directory-creation.html 
 */
int
orion_fs_mkdirs(const char * restrict path, mode_t mode)
{
    char *tmp = strdup(path);
    if (tmp == NULL) return -1;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) == -1) {
                if (errno != EEXIST) {  /* don't care about EEXIST errors*/
                    free(tmp);
                    return -1;
                }
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) == -1) {
        if (errno != EEXIST) {  /* don't care about EEXIST errors*/
            free(tmp);
            return -1;
        }
    }

    free(tmp);
    return 0;
}

/* open a pidfile if not already in use by a running process */
int
orion_fs_open_pidfile(const char * restrict pidfile)
{
    int fd, len, loc_errno, pid;
    char buf[32];  /* no way a process ID can be this long */

    /*
     * If the named file already exists, check if its last-modified date is
     * before the boot-time of the system.  If so, then presumably the system
     * has rebooted prior since this file was created and thus the file is no
     * longer valid.  Its important to delete the file in this case - although
     * normally its contents will not match the pid of any currently running
     * process (in which case it will be deleted anyways), its possible to get
     * unlucky and some running process will just happen to match whatever PID
     * is in that file which will confuse us and make us think that the program
     * we are trying to start is already running.
     */
    struct timespec tp;
    if (clock_gettime(CLOCK_MONOTONIC, &tp) == -1)
        return -1;

    struct stat fstat;
    if (stat(pidfile, &fstat) == 0) {
        /* pidfile exists - check its age (using 'seconds' fields only) */
        if (fstat.st_mtimespec.tv_sec < tp.tv_sec) {
            /* pidfile is older than system uptime - its invalid */
            if (unlink(pidfile) == -1)
                return -1;
        }
    } else {
        /* pidfile could not be read for some reason */
        if (errno == ENOTDIR) {
            /* no problem, pidfile doesn't exist and we need some dirs */
            if (orion_fs_mkdirs(dirname(pidfile), S_IRWXU) == -1) {
                /* failed to make directories */
                return -1;
            }
        } else if (errno == ENOENT) {
            /* no problem, directory path exists, but pidfile does not */
        } else {
            /* problem!  all other errors are fatal to this method */
            return -1;
        }
    }

    fd = open(pidfile, O_WRONLY | O_CREAT | O_EXCL, 0664);
    if (fd == -1) {
        if (errno == EEXIST) {
            /* ok, pidfile already exists, but is process running? */
            fd = open(pidfile, O_RDONLY);
            if (fd == -1) return -1;  /* failed to open file */
            len = read(fd, buf, sizeof(buf));
            loc_errno = errno;
            close(fd);
            if (len == -1) {
                /* read failed */
                errno = loc_errno;
                return -1;
            }

            if (strlen(buf) == 0) {
                /* empty pidfile; that's fine */
            }
            else {
                pid = strtol(buf, NULL, 10);
                if (pid == 0) {
                    /* conversion of pidfile text to pid failed */
                    errno = EINVAL;
                    return -1;
                }

                /* poke listed process to see if it exists */
                if (kill(pid, 0) == -1) {
                    if (errno != ESRCH) {
                        /* some error other than 'process does not exist' */
                        return -1;
                    }
                    /* else, fall through */
                } else {
                    /* 
                     * if kill() succeeds, then the process is running; we
                     * communicate this with a return value of -2
                     */
                    return -2;
                }
            }

            /* process does not exist (or pidfile was empty) */
            if (unlink(pidfile) == -1) {
                /* failed to delete pidfile */
                return -1;
            } else {
                /* 
                 * successfully deleted pidfile; now try again to create/open it
                 */
                fd = open(pidfile, O_WRONLY | O_CREAT | O_EXCL, 0664);
                if (fd == -1) {
                    /* bah, I give up! */
                    return -1;
                }
                /* else, fall through */
            }
        }
    }
    return fd;
}
