#-------------------------------------------------------------------------------
# Name:         sfp_shodan
# Purpose:      Query SHODAN for identified IP addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_shodan(SpiderFootPlugin):
    """SHODAN:Obtain information from SHODAN about identified IP addresses."""

    # Default options
    opts = { 
        "apikey":   ""
    }

    # Option descriptions
    optdescs = {
        "apikey":   "Your SHODAN API Key."
    }

    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["OPERATING_SYSTEM", "DEVICE_TYPE", 
            "TCP_PORT_OPEN", "TCP_PORT_OPEN_BANNER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['apikey'] == "":
            sf.error("You enabled sfp_shodan but did not set an API key!", False)
            return None

       # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        res = sf.fetchUrl("https://api.shodan.io/shodan/host/" + eventData + \
            "?key=" + self.opts['apikey'],
            timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] == None:
            sf.info("No SHODAN info found for " + eventData)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            sf.error("Error processing JSON response from SHODAN.", False)
            return None

        os = info.get('os')
        devtype = info.get('devicetype')

        if os != None:
            # Notify other modules of what you've found
            evt = SpiderFootEvent("OPERATING_SYSTEM", os, self.__name__, event)
            self.notifyListeners(evt)

        if devtype != None:
            # Notify other modules of what you've found
            evt = SpiderFootEvent("DEVICE_TYPE", devtype, self.__name__, event)
            self.notifyListeners(evt)


        sf.info("Found SHODAN data for " + eventData)
        for rec in info['data']:
            port = str(rec.get('port'))
            banner = rec.get('banner')

            if port != None:
                # Notify other modules of what you've found
                evt = SpiderFootEvent("TCP_PORT_OPEN", port, self.__name__, event)
                self.notifyListeners(evt)

            if banner != None:
                # Notify other modules of what you've found
                evt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", banner, self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_shodan class
