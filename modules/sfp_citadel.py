# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_citadel
# Purpose:      SpiderFoot plug-in to search citadel.pw using their API, for
#               potential data breaches.
#
# Author:      sn <citadel.pw@protonmail.com>
#
# Created:     15/08/2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_citadel(SpiderFootPlugin):
    """Citadel Engine:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:apikey:Searches Leak-Lookup.com's database of breaches."""

    # Default options
    opts = {
        "api_key": "",
        "timeout": 60
    }
    optdescs = {
        "api_key": "Leak-Lookup API key. Without this you're limited to the public API.",
        "timeout": "Custom timeout due to heavy traffic at times."
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "Leak-Lookup.com"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['EMAILADDR']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        try:
            self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

            # Don't look up stuff twice
            if eventData in self.results:
                self.sf.debug("Skipping " + eventData + " as already searched.")
                return None
            else:
                self.results[eventData] = True

            url = "http://leak-lookup.com/api/search" 
               
            if self.opts['api_key']:
                postdata = "key={}".format( self.opts['api_key'] )  
            else:
                postdata = "key=6ce4f0a0c7b776809adb0f90473ea0e4"

            postdata += "&type=email_address&query={}".format( eventData )
                
            res = self.sf.fetchUrl(url, data=postdata timeout=self.opts['timeout'], 
                                   useragent=self.opts['_useragent'])

            if res['content'] is None or '"error": "true"' in res['content']:
                self.sf.error("Error encountered processing " + eventData, False)
                return None

            data = json.loads(res['content'])

            for site in data["message"]:
                self.sf.info("Found Leak-Lookup entry for {}: {}".format( eventData, site ) )
                evt = SpiderFootEvent( "EMAILADDR_COMPROMISED", "{} [{}]".format( eventData, site ), self.__name__, event )
                self.notifyListeners(evt)
            
            return None
            
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            self.sf.error(message, False)

# End of sfp_citadel class

