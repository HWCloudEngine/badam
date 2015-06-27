'''
Created on 2014-2-13

'''
import logging
import sys
import os
import logging.handlers
from logging.handlers import SysLogHandler
import socket
from logging import LogRecord

def init(name, invalid=False, output=False):

    global g_FS_logger_invalid
    g_FS_logger_invalid = invalid

    global g_FS_logger
    g_FS_logger = FSLogger(name)

    if invalid:
        return

    global g_FS_logger_output
    g_FS_logger_output = output
        
    formatter = logging.Formatter("%(name)s %(levelname)s [type:%(type)s] [pid:%(process)d] [%(threadName)s] [%(filename)s:%(lineno)d %(funcName)s] %(message)s")
    #syslog = FSSysLogHandler()
    #syslog.setFormatter(formatter)
    #g_FS_logger.addHandler(syslog)

    file_handler = logging.FileHandler(name)
    file_handler.setFormatter(formatter)
    g_FS_logger.addHandler(file_handler)

    g_FS_logger.setLevel(logging.DEBUG)
    
def debug(msg, *args, **kwargs):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.debug(msg, *args, **kwargs)
    
def info(msg, *args, **kwargs):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.info(msg, *args, **kwargs)
    
def warning(msg, *args, **kwargs):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.warning(msg, *args, **kwargs)
    
def warn(msg, *args, **kwargs):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.warning(msg, *args, **kwargs)

def error(msg, *args, **kwargs):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.error(msg, *args, **kwargs)

def critical(msg, *args, **kwargs):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.critical(msg, *args, **kwargs)

def setLevel(level):

    global g_FS_logger_invalid
    if g_FS_logger_invalid:
        return

    global g_FS_logger
    g_FS_logger.setLevel(level)
    
class FSSysLogHandler(SysLogHandler):
    def __init__(self):
        SysLogHandler.__init__(self,facility=SysLogHandler.LOG_LOCAL1)
        self.socket.bind(("127.0.0.1",0))
        
    def emit(self, record):
        """
        Emit a record.

        The record is formatted, and then sent to the syslog server. If
        exception information is present, it is NOT sent to the server.
        """
        msg = self.format(record)
        
        # We need to convert record level to lowercase, maybe this will
        # change in the future.
        
        msg = self.log_format_string % (
            self.encodePriority(self.facility,
                                self.mapPriority(record.levelname)),
                                msg)
        # Treat unicode messages as required by RFC 5424
        if logging.handlers._unicode and type(msg) is unicode:
            msg = msg.encode('utf-8')
            if logging.handlers.codecs:
                pass

        global g_FS_logger_output
        if g_FS_logger_output:
            print msg

        try:
            if self.unixsocket:
                try:
                    self.socket.send(msg)
                except socket.error:
                    self._connect_unixsocket(self.address)
                    self.socket.send(msg)
            else:
                if len(msg) > 65500:
                    msg = msg[:65500] + '\000'
                self.socket.sendto(msg, self.address)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def handleError(self, record):
        pass
        
class FSLogger(logging.Logger):
    
    def __init__(self,name):
        logging.Logger.__init__(self,name)
        
    def findCaller(self):
        """
        Find the stack frame of the caller so that we can note the source
        file name, line number and function name.
        """
        f = currentframe()
        #On some versions of IronPython, currentframe() returns None if
        #IronPython isn't run with -X:Frames.
        if f is not None:
            f = f.f_back
        rv = "(unknown file)", 0, "(unknown function)"
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename == logging._srcfile:
                f = f.f_back
                continue
            rv = (co.co_filename, f.f_lineno, co.co_name)
            break
        return rv
    def makeRecord(self, name, level, fn, lno, msg, args, exc_info, func=None, extra=None):
        """
        A factory method which can be overridden in subclasses to create
        specialized LogRecords.
        """
        rv = LogRecord(name, level, fn, lno, msg, args, exc_info, func)
        if extra is not None:
            for key in extra:
                if (key in ["message", "asctime"]) or (key in rv.__dict__):
                    raise KeyError("Attempt to overwrite %r in LogRecord" % key)
                rv.__dict__[key] = extra[key]
                
            if not extra.has_key("type"):
                rv.__dict__["type"] = "run"
        else:
            rv.__dict__["type"] = "run"
        return rv

def currentframe():
    """Return the frame object for the caller's stack frame."""
    try:
        raise Exception
    except:
        return sys.exc_info()[2].tb_frame.f_back

if hasattr(sys, '_getframe'): currentframe = lambda: sys._getframe(4)