#!/usr/local/bin/python

#
# IMPORTS
#

# system modules
import datetime
import os


#
# CLASSES
#

class HourlyLog:
    def __init__(self, outdir):
        self.outdir = outdir
        self.log = None

    def close(self):
        self.log.close()
        self.log = None
    
    def open_log(self, dt):
        month_names = ["jan", "feb", "mar", "apr", "may", "jun",
                       "jul", "aug", "sep", "oct", "nov", "dec"]
        
        dirname = "%s/%s-%02d" % (self.outdir, month_names[dt.month-1], dt.day)
        if not os.path.exists(dirname):
            os.mkdir(dirname)

        logname = "%s/%02d-argos-server.log" % (dirname, dt.hour)
        return open(logname, "a", 1)  # open line-buffered

    def write(self, line, dt=None):
        if dt is None:
            dt = datetime.datetime.now()

        if self.log is None:
            self.log = self.open_log(dt)
            self.log_hour = dt.hour
        elif self.log_hour != dt.hour:
            self.log.close()
            del self.log
            self.log = self.open_log(dt)
            self.log_hour = dt.hour

        if line[-1] != "\n":
            line += "\n"
        self.log.write(line)

