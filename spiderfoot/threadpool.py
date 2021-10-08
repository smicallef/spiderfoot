import queue
import logging
import threading
from time import sleep
from contextlib import suppress


class SpiderFootThreadPool:
    """
    Each thread in the pool is spawned only once, and reused for best performance.

    Example 1: using map()
        with SpiderFootThreadPool(self.opts["_maxthreads"]) as pool:
            # callback("a", "arg1"), callback("b", "arg1"), ...
            for result in pool.map(
                    callback,
                    ["a", "b", "c", "d"],
                    "arg1",
                    taskName="sfp_testmodule"
                    saveResult=True
                ):
                yield result

    Example 2: using submit()
        with SpiderFootThreadPool(self.opts["_maxthreads"]) as pool:
            pool.start()
            # callback("arg1"), callback("arg2")
            pool.submit(callback, "arg1", taskName="sfp_testmodule", saveResult=True)
            pool.submit(callback, "arg2", taskName="sfp_testmodule", saveResult=True)
            for result in pool.shutdown()["sfp_testmodule"]:
                yield result
    """

    def __init__(self, threads=100, qsize=10, name=None):
        """Initialize the SpiderFootThreadPool class.

        Args:
            threads: Max number of threads
            qsize: Queue size
            name: Name
        """
        if name is None:
            name = ""

        self.log = logging.getLogger(f"spiderfoot.{__name__}")
        self.threads = int(threads)
        self.qsize = int(qsize)
        self.pool = [None] * self.threads
        self.name = str(name)
        self.inputThread = None
        self.inputQueues = dict()
        self.outputQueues = dict()
        self._stop = False
        self._lock = threading.Lock()

    def start(self):
        self.log.debug(f'Starting thread pool "{self.name}" with {self.threads:,} threads')
        for i in range(self.threads):
            t = ThreadPoolWorker(pool=self, name=f"{self.name}_worker_{i + 1}")
            t.start()
            self.pool[i] = t

    @property
    def stop(self):
        return self._stop

    @stop.setter
    def stop(self, val):
        assert val in (True, False), "stop must be either True or False"
        for t in self.pool:
            with suppress(Exception):
                t.stop = val
        self._stop = val

    def shutdown(self, wait=True):
        """Shut down the pool.

        Args:
            wait (bool): Whether to wait for the pool to finish executing

        Returns:
            results (dict): (unordered) results in the format: {"taskName": [returnvalue1, returnvalue2, ...]}
        """
        results = dict()
        self.log.debug(f'Shutting down thread pool "{self.name}" with wait={wait}')
        if wait:
            while not self.finished and not self.stop:
                with self._lock:
                    outputQueues = list(self.outputQueues)
                for taskName in outputQueues:
                    moduleResults = list(self.results(taskName))
                    try:
                        results[taskName] += moduleResults
                    except KeyError:
                        results[taskName] = moduleResults
                sleep(.1)
        self.stop = True
        # make sure input queues are empty
        with self._lock:
            inputQueues = list(self.inputQueues.values())
        for q in inputQueues:
            with suppress(Exception):
                while 1:
                    q.get_nowait()
            with suppress(Exception):
                q.close()
        # make sure output queues are empty
        with self._lock:
            outputQueues = list(self.outputQueues.items())
        for taskName, q in outputQueues:
            moduleResults = list(self.results(taskName))
            try:
                results[taskName] += moduleResults
            except KeyError:
                results[taskName] = moduleResults
            with suppress(Exception):
                q.close()
        return results

    def submit(self, callback, *args, **kwargs):
        """Submit a function call to the pool.
        The "taskName" and "maxThreads" arguments are optional.

        Args:
            callback (function): callback function
            *args: Passed through to callback
            **kwargs: Passed through to callback, except for taskName and maxThreads
        """
        taskName = kwargs.get('taskName', 'default')
        maxThreads = kwargs.pop('maxThreads', 100)
        # block if this module's thread limit has been reached
        while self.countQueuedTasks(taskName) >= maxThreads:
            sleep(.01)
            continue
        self.log.debug(f"Submitting function \"{callback.__name__}\" from module \"{taskName}\" to thread pool \"{self.name}\"")
        self.inputQueue(taskName).put((callback, args, kwargs))

    def countQueuedTasks(self, taskName):
        """For the specified task, returns the number of queued function calls
        plus the number of functions which are currently executing

        Args:
            taskName (str): Name of task

        Returns:
            the number of queued function calls plus the number of functions which are currently executing
        """
        queuedTasks = 0
        with suppress(Exception):
            queuedTasks += self.inputQueues[taskName].qsize()
        runningTasks = 0
        for t in self.pool:
            with suppress(Exception):
                if t.taskName == taskName:
                    runningTasks += 1
        return queuedTasks + runningTasks

    def inputQueue(self, taskName="default"):
        try:
            return self.inputQueues[taskName]
        except KeyError:
            self.inputQueues[taskName] = queue.Queue(self.qsize)
            return self.inputQueues[taskName]

    def outputQueue(self, taskName="default"):
        try:
            return self.outputQueues[taskName]
        except KeyError:
            self.outputQueues[taskName] = queue.Queue(self.qsize)
            return self.outputQueues[taskName]

    def map(self, callback, iterable, *args, **kwargs):  # noqa: A003
        """
        Args:
            iterable: each entry will be passed as the first argument to the function
            callback: the function to thread
            args: additional arguments to pass to callback function
            kwargs: keyword arguments to pass to callback function

        Yields:
            return values from completed callback function
        """
        taskName = kwargs.get("taskName", "default")
        self.inputThread = threading.Thread(target=self.feedQueue, args=(callback, iterable, args, kwargs))
        self.inputThread.start()
        self.start()
        sleep(.1)
        yield from self.results(taskName, wait=True)

    def results(self, taskName="default", wait=False):
        while 1:
            result = False
            with suppress(Exception):
                while 1:
                    yield self.outputQueue(taskName).get_nowait()
                    result = True
            if self.countQueuedTasks(taskName) == 0 or not wait:
                break
            if not result:
                # sleep briefly to save CPU
                sleep(.1)

    def feedQueue(self, callback, iterable, args, kwargs):
        for i in iterable:
            if self.stop:
                break
            self.submit(callback, i, *args, **kwargs)

    @property
    def finished(self):
        if self.stop:
            return True
        else:
            finishedThreads = [not t.busy for t in self.pool if t is not None]
            try:
                inputThreadAlive = self.inputThread.is_alive()
            except AttributeError:
                inputThreadAlive = False
            inputQueuesEmpty = [q.empty() for q in self.inputQueues.values()]
            return not inputThreadAlive and all(inputQueuesEmpty) and all(finishedThreads)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.shutdown()


class ThreadPoolWorker(threading.Thread):

    def __init__(self, pool, name=None):

        self.log = logging.getLogger(f"spiderfoot.{__name__}")
        self.pool = pool
        self.taskName = ""  # which module submitted the callback
        self.busy = False
        self.stop = False

        super().__init__(name=name)

    def run(self):
        # Round-robin through each module's input queue
        while not self.stop:
            ran = False
            with self.pool._lock:
                inputQueues = list(self.pool.inputQueues.values())
            for q in inputQueues:
                if self.stop:
                    break
                try:
                    self.busy = True
                    callback, args, kwargs = q.get_nowait()
                    self.taskName = kwargs.pop("taskName", "default")
                    saveResult = kwargs.pop("saveResult", False)
                    try:
                        result = callback(*args, **kwargs)
                        ran = True
                    except Exception:  # noqa: B902
                        import traceback
                        self.log.error(f'Error in thread worker {self.name}: {traceback.format_exc()}')
                        break
                    if saveResult:
                        self.pool.outputQueue(self.taskName).put(result)
                except queue.Empty:
                    self.busy = False
                finally:
                    self.busy = False
                    self.taskName = ""
            # sleep briefly to save CPU
            if not ran:
                sleep(.05)
