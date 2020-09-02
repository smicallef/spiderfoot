import hashlib
import random
import time


class SpiderFootEvent():
    """SpiderFootEvent object representing identified data and associated meta data.

    Attributes:
        generated (float): timestamp of event creation time
        eventType (str): event type, e.g. URL_FORM, RAW_DATA, etc.
        confidence (int): how sure are we of this data's validity, 0-100
        visibility (int): how 'visible' was this data, 0-100
        risk (int): how much risk does this data represent, 0-100
        module (str): module from which the event originated
        data (str): event data, e.g. a URL, port number, webpage content, etc.
        sourceEvent (SpiderFootEvent): SpiderFootEvent that triggered this event
        sourceEventHash (str): hash of the SpiderFootEvent event that triggered this event
        hash (str): unique SHA256 hash of the event, or "ROOT"
        moduleDataSource (str): module data source
        actualSource (str): source data of parent event
        __id: unique ID of the event, generated using eventType, generated, module, and a random integer
    """

    _generated = None
    _eventType = None
    _confidence = None
    _visibility = None
    _risk = None
    _module = None
    _data = None
    _sourceEvent = None
    _sourceEventHash = None
    _moduleDataSource = None
    _actualSource = None
    __id = None

    def __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0):
        """Initialize SpiderFoot event object.

        Args:
            eventType (str): event type, e.g. URL_FORM, RAW_DATA, etc.
            data (str): event data, e.g. a URL, port number, webpage content, etc.
            module (str): module from which the event originated
            sourceEvent (SpiderFootEvent): SpiderFootEvent event that triggered this event
            confidence (int): how sure are we of this data's validity, 0-100
            visibility (int): how 'visible' was this data, 0-100
            risk (int): how much risk does this data represent, 0-100

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
        """

        self._generated = time.time()
        self.data = data
        self.eventType = eventType
        self.module = module
        self.confidence = confidence
        self.visibility = visibility
        self.risk = risk
        self.sourceEvent = sourceEvent
        self.__id = f"{self.eventType}{self.generated}{self.module}{random.SystemRandom().randint(0, 99999999)}"

    @property
    def generated(self):
        """
        Returns:
            float: timestamp of event creation time
        """
        return self._generated

    @property
    def eventType(self):
        return self._eventType

    @property
    def confidence(self):
        """
        Returns:
            int: How sure are we of this data's validity (0 to 100)
        """
        return self._confidence

    @property
    def visibility(self):
        """
        Returns:
            int: How 'visible' was this data (0 to 100)
        """
        return self._visibility

    @property
    def risk(self):
        """
        Returns:
            int: How much risk does this data represent (0 to 100)
        """
        return self._risk

    @property
    def module(self):
        return self._module

    @property
    def data(self):
        return self._data

    @property
    def sourceEvent(self):
        return self._sourceEvent

    @property
    def sourceEventHash(self):
        return self._sourceEventHash

    @property
    def actualSource(self):
        """actual source"""
        return self._actualSource

    @property
    def moduleDataSource(self):
        """module data source"""
        return self._moduleDataSource

    @property
    def hash(self):
        """Unique hash of this event.

        Returns:
            str: unique SHA256 hash of the event, or "ROOT"
        """
        if self.eventType == "ROOT":
            return "ROOT"

        digestStr = self.__id.encode('raw_unicode_escape')
        return hashlib.sha256(digestStr).hexdigest()

    @eventType.setter
    def eventType(self, eventType):
        """
        Args:
            eventType (str): type of data for this event

        Raises:
            TypeError: confidence type was invalid
            ValueError: confidence value was invalid
        """

        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()")

        if not eventType:
            raise ValueError("eventType is empty")

        self._eventType = eventType

    @confidence.setter
    def confidence(self, confidence):
        """
        Args:
            confidence (int): How sure are we of this data's validitya(0 to 100)

        Raises:
            TypeError: confidence type was invalid
            ValueError: confidence value was invalid
        """

        if not isinstance(confidence, int):
            raise TypeError(f"confidence is {type(confidence)}; expected int()")

        if not 0 <= confidence <= 100:
            raise ValueError(f"confidence value is {confidence}; expected 0 - 100")

        self._confidence = confidence

    @visibility.setter
    def visibility(self, visibility):
        """
        Args:
            visibility (int): How 'visible' was this data (0 to 100)

        Raises:
            TypeError: visibility type was invalid
            ValueError: visibility value was invalid
        """

        if not isinstance(visibility, int):
            raise TypeError(f"visibility is {type(visibility)}; expected int()")

        if not 0 <= visibility <= 100:
            raise ValueError(f"visibility value is {visibility}; expected 0 - 100")

        self._visibility = visibility

    @risk.setter
    def risk(self, risk):
        """
        Args:
            risk (int): How much risk does this data represent (0 to 100)

        Raises:
            TypeError: risk type was invalid
            ValueError: risk value was invalid
        """

        if not isinstance(risk, int):
            raise TypeError(f"risk is {type(risk)}; expected int()")

        if not 0 <= risk <= 100:
            raise ValueError(f"risk value is {risk}; expected 0 - 100")

        self._risk = risk

    @module.setter
    def module(self, module):
        """
        Raises:
            TypeError: module type was invalid
            ValueError: module value was invalid
        """

        if not isinstance(module, str):
            raise TypeError(f"module is {type(module )}; expected str()")

        if not module:
            if self.eventType != "ROOT":
                raise ValueError("module is empty")

        self._module = module

    @data.setter
    def data(self, data):
        """
        Raises:
            TypeError: data type was invalid
            ValueError: data value was invalid
        """

        if not isinstance(data, str):
            raise TypeError(f"data is {type(data)}; expected str()")

        if not data:
            raise ValueError(f"data is empty: '{str(data)}'")

        self._data = data

    @sourceEvent.setter
    def sourceEvent(self, sourceEvent):
        """
        Raises:
            TypeError: sourceEvent type was invalid
        """

        # "ROOT" is a special "hash" reserved for elements with no parent,
        # such as targets provided via the web UI or CLI.
        if self.eventType == "ROOT":
            self._sourceEvent = None
            self._sourceEventHash = "ROOT"
            return

        if not isinstance(sourceEvent, SpiderFootEvent):
            raise TypeError(f"sourceEvent is {type(sourceEvent)}; expected SpiderFootEvent()")

        self._sourceEvent = sourceEvent
        self._sourceEventHash = self.sourceEvent.hash

    @actualSource.setter
    def actualSource(self, actualSource):
        self._actualSource = actualSource

    @moduleDataSource.setter
    def moduleDataSource(self, moduleDataSource):
        self._moduleDataSource = moduleDataSource

    def asDict(self):
        """
        Returns:
            dict: event as dictionary
        """

        evtDict = {
            'generated': int(self.generated),
            'type': self.eventType,
            'data': self.data,
            'module': self.module,
            'source': ''
        }

        if self.sourceEvent is not None:
            if self.sourceEvent.data is not None:
                evtDict['source'] = self.sourceEvent.data

        return evtDict

    def getHash(self):
        """Required for SpiderFoot HX compatibility of modules"""
        return self.hash

# end of SpiderFootEvent class
