"""
Custom log output
"""

import sys
import logging

TEXT_NORMAL = 0
TEXT_BOLD = 1
TEXT_RED = 31
TEXT_GREEN = 32
TEXT_YELLOW = 33
TEXT_BLUE = 34
TEXT_MAGENTA = 35
TEXT_CYAN = 36


def get_logger():
    return logging.getLogger('exifread')


def setup_logger(debug, color):
    """Configure the logger."""
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logger = logging.getLogger('exifread')
    stream = Handler(log_level, debug, color)
    logger.addHandler(stream)
    logger.setLevel(log_level)


class Formatter(logging.Formatter):

    def __init__(self, debug=False, color=False):
        self.color = color
        self.debug = debug
        if self.debug:
            log_format = '%(levelname)-6s %(message)s'
        else:
            log_format = '%(message)s'
        logging.Formatter.__init__(self, log_format)

    def format(self, record):
        if self.debug and self.color:
            if record.levelno >= logging.CRITICAL:
                color = TEXT_RED
            elif record.levelno >= logging.ERROR:
                color = TEXT_RED
            elif record.levelno >= logging.WARNING:
                color = TEXT_YELLOW
            elif record.levelno >= logging.INFO:
                color = TEXT_GREEN
            elif record.levelno >= logging.DEBUG:
                color = TEXT_CYAN
            else:
                color = TEXT_NORMAL
            record.levelname = "\x1b[%sm%s\x1b[%sm" % (color, record.levelname, TEXT_NORMAL)
        return logging.Formatter.format(self, record)


class Handler(logging.StreamHandler):

    def __init__(self, log_level, debug=False, color=False):
        self.color = color
        self.debug = debug
        logging.StreamHandler.__init__(self, sys.stdout)
        self.setFormatter(Formatter(debug, color))
        self.setLevel(log_level)
"""
    def emit(self, record):
        record.msg = "\x1b[%sm%s\x1b[%sm" % (TEXT_BOLD, record.msg, TEXT_NORMAL)
        logging.StreamHandler.emit(self, record)
"""