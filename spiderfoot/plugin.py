import logging
import threading
import queue
from time import sleep


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

    log = logging.getLogger(__name__)

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
    # Error state of the module
    errorState = False
    # SOCKS proxy
    socksProxy = None

    def __init__(self):
        """Not really needed in most cases."""
        pass

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
                self.log.exception(f"Module ({listener.__module__}) encountered an error: {e}")

    def checkForStop(self):
        """For modules to use to check for when they should give back control.

        Returns:
            bool
        """
        if not self.__scanId__:
            return False

        scanstatus = self.__sfdb__.scanInstanceGet(self.__scanId__)

        if not scanstatus:
            return False

        if scanstatus[5] == "ABORT-REQUESTED":
            return True

        return False

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

    def start(self):
        """Kick off the work (for some modules nothing will happen here, but instead
        the work will start from the handleEvent() method.
        Will usually be overriden by the implementer.
        """

        return

    class ThreadPool:
        """
        A spiderfoot-integrated threading pool

        Example:

            with self.threadPool(self.opts["_maxthreads"]) as pool:
                for result in pool.map(
                        ['a', 'b', 'c', 'd'],
                        self.functionToThread
                    ):
                    yield result
        """

        def __init__(self, sfp, threads=100, name=None):

            if name is None:
                name = ""

            self.sfp = sfp
            self.threads = int(threads)
            self.pool = [None] * self.threads
            self.name = name
            self.result_queue = queue.Queue()

        @staticmethod
        def execute(func, result_queue, entry, args=(), kwargs={}):
            """Executes given function and places return value in result queue

            Args:
                func: the function to call (the callback)
                result_queue: queue in which to place the return value
                entry: first argument to callback function
                args: additional arguments to pass to callback function
                kwargs: keyword arguments to pass to callback function
            """

            result_queue.put(func(entry, *args, **kwargs))

        def map(self, iterable, callback, args=None, kwargs=None, name=""):
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

            for entry in iterable:

                started = False
                while not started and not self.sfp.checkForStop():
                    for i, t in enumerate(self.pool):

                        for result in self.results:
                            yield result

                        if t is None or not t.is_alive():
                            extended_args = (callback, self.result_queue, entry) + args
                            self.pool[i] = threading.Thread(target=self.execute, args=extended_args, kwargs=kwargs, name=f"{self.name}_{name}")
                            self.pool[i].start()
                            started = True
                            break

            # wait for threads to finish
            while 1:
                if self.sfp.checkForStop():
                    return

                for result in self.results:
                    yield result

                finished_threads = [t is None or not t.is_alive() for t in self.pool]
                if all(finished_threads):
                    break

            for result in self.results:
                yield result

        @property
        def results(self):

            while 1:
                try:
                    yield self.result_queue.get_nowait()
                except queue.Empty:
                    # sleep briefly to save CPU
                    sleep(.01)
                    break

        def __enter__(self):

            return self

        def __exit__(self, exception_type, exception_value, traceback):

            # Make sure the queue is empty before exiting
            try:
                while 1:
                    try:
                        self.result_queue.get_nowait()
                    except queue.Empty:
                        break
            except Exception:
                pass

    def threadPool(self, *args, **kwargs):

        return self.ThreadPool(self, *args, **kwargs)

# end of SpiderFootPlugin class
