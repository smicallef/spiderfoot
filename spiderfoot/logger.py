import logging
import sys
from contextlib import suppress
from logging.handlers import QueueHandler, QueueListener
from pathlib import Path

from spiderfoot import SpiderFootDb

log_format = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")


class SpiderFootSqliteLogHandler(logging.Handler):
    """Handler for logging to SQLite database.

    This ensure all sqlite logging is done from a single
    process and a single database handle.
    """

    def __init__(self, opts: dict) -> None:
        """TBD.

        Args:
            opts (dict): TBD
        """
        self.opts = opts
        self.dbh = None
        super().__init__()

    def emit(self, record: 'logging.LogRecord') -> None:
        """TBD

        Args:
            record (logging.LogRecord): Log event record
        """
        if self.dbh is None:
            # Create a new database handle when the first log record is received
            self.makeDbh()
        scanId = getattr(record, "scanId", None)
        component = getattr(record, "component", None)
        if scanId:
            level = ("STATUS" if record.levelname == "INFO" else record.levelname)
            logResult = self.dbh.scanLogEvent(scanId, level, record.getMessage(), component=component)
            if logResult is False:
                # Try to recreate database handle if insert failed
                self.makeDbh()
                self.dbh.scanLogEvent(scanId, level, record.getMessage(), component=component)

    def makeDbh(self) -> None:
        """TBD."""
        self.dbh = SpiderFootDb(self.opts)


def logListenerSetup(loggingQueue, opts: dict = None) -> 'logging.handlers.QueueListener':
    """Create and start a SpiderFoot log listener in its own thread.

    This function should be called as soon as possible in the main
    process, or whichever process is attached to stdin/stdout.

    Args:
        loggingQueue (Queue): Queue (accepts both normal and multiprocessing queue types)
                              Must be instantiated in the main process.
        opts (dict): SpiderFoot config

    Returns:
        spiderFootLogListener (logging.handlers.QueueListener): Log listener
    """
    if opts is None:
        opts = dict()
    doLogging = opts.get("__logging", True)
    debug = opts.get("_debug", False)
    logLevel = (logging.DEBUG if debug else logging.INFO)

    # Log to terminal
    console_handler = logging.StreamHandler(sys.stderr)

    # Log debug messages to file
    log_dir = Path(__file__).parent.parent / "log"
    debug_handler = logging.handlers.TimedRotatingFileHandler(
        str(log_dir / "spiderfoot.debug.log"),
        when="d",
        interval=1,
        backupCount=30
    )

    # Log error messages to file
    error_handler = logging.handlers.TimedRotatingFileHandler(
        str(log_dir / "spiderfoot.error.log"),
        when="d",
        interval=1,
        backupCount=30
    )

    # Set log level
    console_handler.setLevel(logLevel)
    debug_handler.setLevel(logging.DEBUG)
    error_handler.setLevel(logging.WARN)

    # Set log format
    console_handler.setFormatter(log_format)
    debug_handler.setFormatter(log_format)
    error_handler.setFormatter(log_format)

    if doLogging:
        handlers = [console_handler, debug_handler, error_handler]
    else:
        handlers = []

    import atexit
    if doLogging and opts is not None:
        sqlite_handler = SpiderFootSqliteLogHandler(opts)
        sqlite_handler.setLevel(logLevel)
        sqlite_handler.setFormatter(log_format)
        handlers.append(sqlite_handler)
    spiderFootLogListener = QueueListener(loggingQueue, *handlers)
    spiderFootLogListener.start()
    atexit.register(stop_listener, spiderFootLogListener)
    return spiderFootLogListener


def logWorkerSetup(loggingQueue) -> 'logging.Logger':
    """Root SpiderFoot logger.

    Args:
        loggingQueue (Queue): TBD

    Returns:
        logging.Logger: Logger
    """
    log = logging.getLogger("spiderfoot")
    log.setLevel(logging.DEBUG)
    queue_handler = QueueHandler(loggingQueue)
    log.addHandler(queue_handler)
    return log


def stop_listener(listener: 'logging.handlers.QueueListener') -> None:
    """TBD.

    Args:
        listener: (logging.handlers.QueueListener): TBD
    """
    with suppress(Exception):
        listener.stop()
