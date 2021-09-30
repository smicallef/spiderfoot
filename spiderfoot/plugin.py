from contextlib import suppress
import io
import logging
import os
import queue
import sys
import threading
from time import sleep
import traceback

# begin logging overrides
# these are copied from the python logging module
# https://github.com/python/cpython/blob/main/Lib/logging/__init__.py

if hasattr(sys, 'frozen'):  # support for py2exe
    _srcfile = f"logging{os.sep}__init__{__file__[-4:]}"
elif __file__[-4:].lower() in ['.pyc', '.pyo']:
    _srcfile = __file__[:-4] + '.py'
else:
    _srcfile = __file__
_srcfile = os.path.normcase(_srcfile)


class SpiderFootPluginLogger(logging.Logger):
    """Used only in SpiderFootPlugin to prevent modules
    from having to initialize their own loggers.

    Preserves filename, module, line numbers, etc. from the caller.
    """

    def findCaller(self, stack_info=False, stacklevel=1):
        """Find the stack frame of the caller so that we can note the source
        file name, line number and function name.

        Args:
            stack_info: boolean
            stacklevel: int

        Returns:
            rv: tuple, filename, line number, module name, and stack trace
        """
        f = logging.currentframe()
        # On some versions of IronPython, currentframe() returns None if
        # IronPython isn't run with -X:Frames.
        if f is not None:
            f = f.f_back
        orig_f = f
        while f and stacklevel > 1:
            f = f.f_back
            stacklevel -= 1
        if not f:
            f = orig_f
        rv = "(unknown file)", 0, "(unknown function)", None
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename in (logging._srcfile, _srcfile):  # This is the only change
                f = f.f_back
                continue
            sinfo = None
            if stack_info:
                sio = io.StringIO()
                sio.write('Stack (most recent call last):\n')
                traceback.print_stack(f, file=sio)
                sinfo = sio.getvalue()
                if sinfo[-1] == '\n':
                    sinfo = sinfo[:-1]
                sio.close()
            rv = (co.co_filename, f.f_lineno, co.co_name, sinfo)
            break
        return rv  # noqa R504

# end of logging overrides


class SpiderFootPlugin():
    """SpiderFootPlugin module object

    Attributes:
        _stopScanning (bool): Will be set to True by the controller if the user aborts scanning
        listenerModules (list): Modules that will be notified when this module produces events
        _currentEvent (SpiderFootEvent): Current event being processed
        _currentTarget (str): Target currently being acted against
        _name_: Name of this module, set at startup time
        __sfdb__: Direct handle to the database - not to be directly used
                  by modules except the sfp__stor_db module.
        __scanId__: ID of the scan the module is running against
        __datasource__: (Unused) tracking of data sources
        __outputFilter: If set, events not matching this list are dropped
        _priority (int): Priority, smaller numbers should run first
        errorState (bool): error state of the module
        socksProxy (str): SOCKS proxy
    """

    # Will be set to True by the controller if the user aborts scanning
    _stopScanning = False
    # Modules that will be notified when this module produces events
    _listenerModules = list()
    # Current event being processed
    _currentEvent = None
    # Target currently being acted against
    _currentTarget = None
    # Name of this module, set at startup time
    __name__ = "module_name_not_set!"
    # Direct handle to the database - not to be directly used
    # by modules except the sfp__stor_db module.
    __sfdb__ = None
    # ID of the scan the module is running against
    __scanId__ = None
    # (only used in SpiderFoot HX) tracking of data sources
    __dataSource__ = None
    # If set, events not matching this list are dropped
    __outputFilter__ = None
    # Priority, smaller numbers should run first
    _priority = 1
    # Plugin meta information
    meta = None
    # Error state of the module
    errorState = False
    # SOCKS proxy
    socksProxy = None
    # Queue for incoming events
    incomingEventQueue = None
    # Queue for produced events
    outgoingEventQueue = None
    # SpiderFoot object, set in each module's setup() function
    sf = None
    # Configuration, set in each module's setup() function
    opts = dict()

    def __init__(self):
        # Whether the module is currently processing data
        self._running = False
        # Holds the thread object when module threading is enabled
        self.thread = None
        # logging overrides
        self._log = None

    @property
    def log(self):
        if self._log is None:
            logging.setLoggerClass(SpiderFootPluginLogger)  # temporarily set logger class
            self._log = logging.getLogger(f"spiderfoot.{self.__name__}")  # init SpiderFootPluginLogger
            logging.setLoggerClass(logging.Logger)  # reset logger class to default
        return self._log

    def _updateSocket(self, socksProxy):
        """Hack to override module's use of socket, replacing it with
        one that uses the supplied SOCKS server.

        Args:
            socksProxy (str): SOCKS proxy
        """
        self.socksProxy = socksProxy

    def clearListeners(self):
        """Used to clear any listener relationships, etc. This is needed because
        Python seems to cache local variables even between threads."""

        self._listenerModules = list()
        self._stopScanning = False

    def setup(self, sf, userOpts={}):
        """Will always be overriden by the implementer.

        Args:
            sf (SpiderFoot): SpiderFoot object
            userOpts (dict): TBD
        """
        pass

    def debug(self, *args, **kwargs):
        """For logging.
        A wrapper around logging.debug() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.debug()
            *kwargs: passed through to logging.debug()
        """
        self.log.debug(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def info(self, *args, **kwargs):
        """For logging.
        A wrapper around logging.info() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.info()
            *kwargs: passed through to logging.info()
        """
        self.log.info(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def error(self, *args, **kwargs):
        """For logging.
        A wrapper around logging.error() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.error()
            *kwargs: passed through to logging.error()
        """
        self.log.error(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def enrichTarget(self, target):
        """Find aliases for a target.

        Note: rarely used in special cases

        Args:
            target (str): TBD
        """
        pass

    def setTarget(self, target):
        """Assigns the current target this module is acting against.

        Args:
            target (SpiderFootTarget): target

        Raises:
            TypeError: target argument was invalid type
        """
        from spiderfoot import SpiderFootTarget

        if not isinstance(target, SpiderFootTarget):
            raise TypeError(f"target is {type(target)}; expected SpiderFootTarget")

        self._currentTarget = target

    def setDbh(self, dbh):
        """Used to set the database handle, which is only to be used
        by modules in very rare/exceptional cases (e.g. sfp__stor_db)

        Args:
            dbh (SpiderFootDb): database handle
        """
        self.__sfdb__ = dbh

    def setScanId(self, scanId):
        """Set the scan ID.

        Args:
            scanId (str): scan instance ID

        Raises:
            TypeError: scanId argument was invalid type
        """
        if not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str")

        self.__scanId__ = scanId

    def getScanId(self):
        """Get the scan ID.

        Returns:
            str: scan ID

        Raises:
            TypeError: Module called getScanId() but no scanId is set.
        """
        if not self.__scanId__:
            raise TypeError("Module called getScanId() but no scanId is set.")

        return self.__scanId__

    def getTarget(self):
        """Gets the current target this module is acting against.

        Returns:
            str: current target

        Raises:
            TypeError: Module called getTarget() but no target is set.
        """
        if not self._currentTarget:
            raise TypeError("Module called getTarget() but no target is set.")

        return self._currentTarget

    def registerListener(self, listener):
        """Listener modules which will get notified once we have data for them to
        work with.

        Args:
            listener: TBD
        """

        self._listenerModules.append(listener)

    def setOutputFilter(self, types):
        self.__outputFilter__ = types

    def tempStorage(self):
        """For future use. Module temporary storage.

        A dictionary used to persist state (in memory) for a module.

        Todo:
            Move all module state to use this, which then would enable a scan to be paused/resumed.

        Note:
            Required for SpiderFoot HX compatibility of modules.

        Returns:
            dict: module temporary state data
        """
        return dict()

    def notifyListeners(self, sfEvent):
        """Call the handleEvent() method of every other plug-in listening for
        events from this plug-in. Remember that those plug-ins will be called
        within the same execution context of this thread, not on their own.

        Args:
            sfEvent (SpiderFootEvent): event

        Raises:
            TypeError: sfEvent argument was invalid type
        """

        from spiderfoot import SpiderFootEvent

        if not isinstance(sfEvent, SpiderFootEvent):
            raise TypeError(f"sfEvent is {type(sfEvent)}; expected SpiderFootEvent")

        eventName = sfEvent.eventType
        eventData = sfEvent.data

        if self.__outputFilter__:
            # Be strict about what events to pass on, unless they are
            # the ROOT event or the event type of the target.
            if eventName not in ('ROOT', self.getTarget().targetType):
                if eventName not in self.__outputFilter__:
                    return

        storeOnly = False  # Under some conditions, only store and don't notify

        if not eventData:
            return

        if self.checkForStop():
            return

        # Look back to ensure the original notification for an element
        # is what's linked to children. For instance, sfp_dns may find
        # xyz.abc.com, and then sfp_ripe obtains some raw data for the
        # same, and then sfp_dns finds xyz.abc.com in there, we should
        # suppress the notification of that to other modules, as the
        # original xyz.abc.com notification from sfp_dns will trigger
        # those modules anyway. This also avoids messy iterations that
        # traverse many many levels.

        # storeOnly is used in this case so that the source to dest
        # relationship is made, but no further events are triggered
        # from dest, as we are already operating on dest's original
        # notification from one of the upstream events.

        prevEvent = sfEvent.sourceEvent
        while prevEvent is not None:
            if prevEvent.sourceEvent is not None:
                if prevEvent.sourceEvent.eventType == sfEvent.eventType and prevEvent.sourceEvent.data.lower() == eventData.lower():
                    storeOnly = True
                    break
            prevEvent = prevEvent.sourceEvent

        # output to queue if applicable
        if self.outgoingEventQueue is not None:
            self.outgoingEventQueue.put(sfEvent)
        # otherwise, call other modules directly
        else:
            self._listenerModules.sort(key=lambda m: m._priority)

            for listener in self._listenerModules:
                if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                    continue

                if storeOnly and "__stor" not in listener.__module__:
                    continue

                listener._currentEvent = sfEvent

                # Check if we've been asked to stop in the meantime, so that
                # notifications stop triggering module activity.
                if self.checkForStop():
                    return

                try:
                    listener.handleEvent(sfEvent)
                except Exception as e:
                    self.sf.error(f"Module ({listener.__module__}) encountered an error: {e}")
                    # set errorState
                    self.errorState = True
                    # clear incoming queue
                    if self.incomingEventQueue:
                        with suppress(queue.Empty):
                            while 1:
                                self.incomingEventQueue.get_nowait()

    def checkForStop(self):
        """For modules to use to check for when they should give back control.

        Returns:
            bool
        """
        # Stop if module is in error state.
        if self.errorState:
            return True

        # If threading is enabled, check the _stopScanning attribute instead.
        # This is to prevent each thread needing its own sqlite db handle.
        if self.outgoingEventQueue is not None and self.incomingEventQueue is not None:
            return self._stopScanning

        if not self.__scanId__:
            return False

        scanstatus = self.__sfdb__.scanInstanceGet(self.__scanId__)

        if not scanstatus:
            return False

        if scanstatus[5] == "ABORT-REQUESTED":
            self._stopScanning = True
            return True

        return False

    @property
    def running(self):
        """Indicates whether the module is currently processing data.
        Modules that process data in pools/batches typically override this method.

        Returns:
            bool
        """
        return self._running

    def watchedEvents(self):
        """What events is this module interested in for input. The format is a list
        of event types that are applied to event types that this module wants to
        be notified of, or * if it wants everything.
        Will usually be overriden by the implementer, unless it is interested
        in all events (default behavior).

        Returns:
            list: list of events this modules watches
        """

        return ['*']

    def producedEvents(self):
        """What events this module produces
        This is to support the end user in selecting modules based on events
        produced.

        Returns:
            list: list of events produced by this module
        """

        return []

    def handleEvent(self, sfEvent):
        """Handle events to this module.
        Will usually be overriden by the implementer, unless it doesn't handle any events.

        Args:
            sfEvent (SpiderFootEvent): event
        """

        return

    def asdict(self):
        return {
            'name': self.meta.get('name'),
            'descr': self.meta.get('summary'),
            'cats': self.meta.get('categories', []),
            'group': self.meta.get('useCases', []),
            'labels': self.meta.get('flags', []),
            'provides': self.producedEvents(),
            'consumes': self.watchedEvents(),
            'meta': self.meta,
            'opts': self.opts,
            'optdescs': self.optdescs,
        }

    def start(self):
        self.thread = threading.Thread(target=self.threadWorker)
        self.thread.start()

    def finish(self):
        """Perform final/cleanup functions before module exits
        Overridden by the implementer
        """

        return

    def threadWorker(self):
        try:
            # create new database handle since we're in our own thread
            from spiderfoot import SpiderFootDb
            self.setDbh(SpiderFootDb(self.opts))
            self.sf._dbh = self.__sfdb__

            if not (self.incomingEventQueue and self.outgoingEventQueue):
                self.sf.error("Please set up queues before starting module as thread")
                return

            while not self.checkForStop():
                try:
                    sfEvent = self.incomingEventQueue.get_nowait()
                except queue.Empty:
                    sleep(.3)
                    continue
                self._running = True
                if sfEvent == 'FINISHED':
                    self.sf.debug(f"{self.__name__}.threadWorker() got \"FINISHED\" from incomingEventQueue.")
                    self.finish()
                else:
                    self.sf.debug(f"{self.__name__}.threadWorker() got event, {sfEvent.eventType}, from incomingEventQueue.")
                    self.handleEvent(sfEvent)
                self._running = False
        except KeyboardInterrupt:
            self.sf.debug(f"Interrupted module {self.__name__}.")
            self._stopScanning = True
        except Exception as e:
            import traceback
            self.sf.error(f"Exception ({e.__class__.__name__}) in module {self.__name__}."
                          + traceback.format_exc())
            # set errorState
            self.sf.debug(f"Setting errorState for module {self.__name__}.")
            self.errorState = True
            # clear incoming queue
            if self.incomingEventQueue:
                self.sf.debug(f"Emptying incomingEventQueue for module {self.__name__}.")
                with suppress(queue.Empty):
                    while 1:
                        self.incomingEventQueue.get_nowait()
                # set queue to None to prevent its use
                # if there are leftover objects in the queue, the scan will hang.
                self.incomingEventQueue = None

        finally:
            self._running = False

    class ThreadPool:
        """
        A spiderfoot-integrated threading pool
        Each thread in the pool is spawned only once, and reused for best performance.

        Example 1: using map()
            with self.threadPool(self.opts["_maxthreads"], saveResults=True) as pool:
                # callback("a", "arg1", kwarg1="kwarg1"), callback("b", "arg1" ...)
                for result in pool.map(
                        callback,
                        ["a", "b", "c", "d"],
                        args=("arg1",)
                        kwargs={kwarg1: "kwarg1"}
                    ):
                    yield result

        Example 2: using submit()
            with self.threadPool(self.opts["_maxthreads"], saveResults=True) as pool:
                pool.start(callback, "arg1", kwarg1="kwarg1")
                # callback(a, "arg1", kwarg1="kwarg1"), callback(b, "arg1" ...)
                pool.submit(a)
                pool.submit(b)
                for result in pool.shutdown():
                    yield result
        """

        def __init__(self, sfp, threads=100, qsize=None, name=None, saveResults=False):
            """Initialize the ThreadPool class.

            Args:
                sfp: A SpiderFootPlugin object
                threads: Max number of threads
                qsize: Queue size
                name: Name
                saveResults: Whether to store the return value of each function call
            """
            if name is None:
                name = ""

            self.sfp = sfp
            self.threads = int(threads)
            try:
                self.qsize = int(qsize)
            except (TypeError, ValueError):
                self.qsize = self.threads * 5
            self.pool = [None] * self.threads
            self.name = str(name)
            self.inputThread = None
            self.inputQueue = queue.Queue(self.qsize)
            if saveResults:
                self.outputQueue = queue.Queue(self.qsize)
            else:
                self.outputQueue = None
            self.stop = False

        def start(self, callback, *args, **kwargs):
            self.sfp.sf.debug(f'Starting thread pool "{self.name}" with {self.threads:,} threads')
            for i in range(self.threads):
                name = kwargs.get('name', 'worker')
                t = ThreadPoolWorker(self.sfp, target=callback, args=args, kwargs=kwargs,
                                     inputQueue=self.inputQueue, outputQueue=self.outputQueue,
                                     name=f"{self.name}_{name}_{i + 1}")
                t.start()
                self.pool[i] = t

        def shutdown(self, wait=True):
            self.sfp.sf.debug(f'Shutting down thread pool "{self.name}" with wait={wait}')
            if wait:
                while not self.finished and not self.sfp.checkForStop():
                    yield from self.results
                    sleep(.1)
            self.stop = True
            for t in self.pool:
                with suppress(Exception):
                    t.stop = True
            # make sure input queue is empty
            with suppress(Exception):
                while 1:
                    self.inputQueue.get_nowait()
            with suppress(Exception):
                self.inputQueue.close()
            yield from self.results
            with suppress(Exception):
                self.outputQueue.close()

        def submit(self, arg, wait=True):
            self.inputQueue.put(arg)

        def map(self, callback, iterable, args=None, kwargs=None, name=""):  # noqa: A003
            """
            Args:
                iterable: each entry will be passed as the first argument to the function
                callback: the function to thread
                args: additional arguments to pass to callback function
                kwargs: keyword arguments to pass to callback function
                name: base name to use for all the threads

            Yields:
                return values from completed callback function
            """

            if args is None:
                args = tuple()

            if kwargs is None:
                kwargs = dict()

            self.inputThread = threading.Thread(target=self.feedQueue, args=(iterable, self.inputQueue))
            self.inputThread.start()

            self.start(callback, *args, **kwargs)
            yield from self.shutdown()

        @property
        def results(self):
            with suppress(Exception):
                while 1:
                    yield self.outputQueue.get_nowait()

        def feedQueue(self, iterable, q):
            for i in iterable:
                if self.stop:
                    break
                while not self.stop:
                    try:
                        q.put_nowait(i)
                        break
                    except queue.Full:
                        sleep(.1)
                        continue

        @property
        def finished(self):
            if self.sfp.checkForStop():
                return True
            else:
                finishedThreads = [not t.busy for t in self.pool if t is not None]
                try:
                    inputThreadAlive = self.inputThread.is_alive()
                except AttributeError:
                    inputThreadAlive = False
                return not inputThreadAlive and self.inputQueue.empty() and all(finishedThreads)

        def __enter__(self):
            return self

        def __exit__(self, exception_type, exception_value, traceback):
            self.shutdown()
            # Make sure queues are empty before exiting
            for q in (self.outputQueue, self.inputQueue):
                with suppress(Exception):
                    while 1:
                        q.get_nowait()

    def threadPool(self, *args, **kwargs):
        return self.ThreadPool(self, *args, **kwargs)


class ThreadPoolWorker(threading.Thread):

    def __init__(self, sfp, inputQueue, outputQueue=None, group=None, target=None,
                 name=None, args=None, kwargs=None, verbose=None):
        if args is None:
            args = tuple()

        if kwargs is None:
            kwargs = dict()

        self.sfp = sfp
        self.inputQueue = inputQueue
        self.outputQueue = outputQueue
        self.busy = False
        self.stop = False

        super().__init__(group, target, name, args, kwargs)

    def run(self):
        while not self.stop:
            try:
                entry = self.inputQueue.get_nowait()
                self.busy = True
                try:
                    result = self._target(entry, *self._args, **self._kwargs)
                except Exception:
                    import traceback
                    self.sfp.sf.error(f'Error in thread worker {self.name}: {traceback.format_exc()}')
                    break
                if self.outputQueue is not None:
                    self.outputQueue.put(result)
            except queue.Empty:
                self.busy = False
                # sleep briefly to save CPU
                sleep(.1)
            finally:
                self.busy = False

# end of SpiderFootPlugin class
