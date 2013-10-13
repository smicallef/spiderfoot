#-------------------------------------------------------------------------------
# Name:         sfp_portscan_basic
# Purpose:      SpiderFoot plug-in for performing a basic port scan of IP
#               addresses identified.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/02/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import socket
import random
import threading
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_portscan_basic(SpiderFootPlugin):
    """Port Scanner:Scans for commonly open TCP ports on Internet-facing systems."""

    # Default options
    opts = {
                            # Commonly used ports on external-facing systems
        'ports':            [ '21', '22', '23', '25', '53', '79', '80', '81', '88', '110','111', 
                            '113', '119', '123', '137', '138', '139', '143', '161', '179',
                            '389', '443', '445', '465', '512', '513', '514', '515', '631', '636',
                            '990', '992', '993', '995', '1080', '8080', '8888', '9000' ],
        'timeout':          15,
        'maxthreads':       10,
        'randomize':        True
    }

    # Option descriptions
    optdescs = {
        'maxthreads':   "Number of ports to try to open simultaneously (number of threads to spawn at once.)",
        'ports':    "The TCP ports to scan. Prefix with an '@' to iterate through a file containing ports to try (one per line), e.g. @C:\ports.txt or @/home/bob/ports.txt. Or supply a URL to load the list from there.",
        'timeout':  "Seconds before giving up on a port.",
        'randomize':    "Randomize the order of ports scanned."
    }

    # Target
    baseDomain = None
    results = dict()
    portlist = list()
    portResults = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        if self.opts['ports'][0].startswith("http://") or \
            self.opts['ports'][0].startswith("https://") or \
            self.opts['ports'][0].startswith("@"):
            self.portlist = sf.optValueToData(self.opts['ports'][0])
        else:
            self.portlist = self.opts['ports']

        # Convert to integers
        self.portlist = [int(x) for x in self.portlist]

        if self.opts['randomize']:
            random.shuffle(self.portlist)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    def tryPort(self, ip, port):
        try:
            sock = socket.create_connection((ip, port), self.opts['timeout'])
            self.portResults[ip + ":" + str(port)] = True
        except Exception as e:
            self.portResults[ip + ":" + str(port)] = False
            return

        # If the port was open, see what we can read
        try:
            self.portResults[ip + ":" + str(port)] = sock.recv(4096)
        except Exception as e:
            sock.close()
            return

    def tryPortWrapper(self, ip, portList):
        self.portResults = dict()
        running = True
        i = 0
        t = []

        # Spawn threads for scanning
        while i < len(portList):
            sf.info("Spawning thread to check port: " + str(portList[i]) + " on " + ip)
            t.append(threading.Thread(name='sfp_portscan_basic_' + str(portList[i]), 
                target=self.tryPort, args=(ip, portList[i])))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("sfp_portscan_basic_"):
                    found = True

            if not found:
                running = False

        return self.portResults

    # Generate both a RAW_DATA and TCP_PORT_OPEN_BANNER event
    def sendEvent(self, resArray, srcEvent):
        for cp in resArray:
            if resArray[cp]:
                sf.info("TCP Port " + cp + " found to be OPEN.")
                (addr, port) = cp.split(":")
                evt = SpiderFootEvent("TCP_PORT_OPEN", port, self.__name__, srcEvent)
                self.notifyListeners(evt)
                if resArray[cp] != "" and resArray[cp] != True:
                    bevt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", resArray[cp],
                        self.__name__, evt)
                    self.notifyListeners(bevt)
                    revt = SpiderFootEvent("RAW_DATA", resArray[cp],
                        self.__name__, evt)
                    self.notifyListeners(revt)


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already scanned.")
            return None
        else:
            self.results[eventData] = True

        i = 0
        portArr = []
        for port in self.portlist:
            if self.checkForStop():
                return None
            
            if i < self.opts['maxthreads']:
                portArr.append(port)    
                i += 1
            else:
                self.sendEvent(self.tryPortWrapper(eventData, portArr), event)
                i = 1
                portArr = []
                portArr.append(port)

        # Scan whatever is remaining
        self.sendEvent(self.tryPortWrapper(eventData, portArr), event)

        return None

# End of sfp_portscan_basic class
