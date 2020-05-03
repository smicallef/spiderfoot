# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dehashed
# Purpose:      Spiderfoot plugin to gather compromised emails, 
#               passwords, hashes, and other data from Dehashed.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     02/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dehashed(SpiderFootPlugin):
    
    """Dehashed:Footprint,Investigate,Passive:Leaks and Breaches:apikey:Gather compromised emails, passwords, hashes and other data"""
    opts = {
        'email': '',
        'api_key': ''
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'email': "Email for accessing Dehashed API",
        'api_key': "Dehashed API Key."
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        # self.tempStorage() basically returns a dict(), but we use self.tempStorage()
        # instead since on SpiderFoot HX, different mechanisms are used to persist
        # data for load distribution, avoiding excess memory consumption and fault 
        # tolerance. This keeps modules transparently compatible with both versions.
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        # The data souce for a module is, by defualt, set to the module name.
        # If you want to override that, for instance in cases where the module
        # is purely processing data from other modules instead of producing
        # data itself, you can do so with the following. Note that this is only
        # utilised in SpiderFoot HX and not the open source version.
        self.__dataSource__ = "Dehashed"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED", "PASSWORD_COMPROMISED",
                "HASH_COMPROMISED", "RAW_RIR_DATA"]

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def query(self, qry):
        headers = {
            'Accept' : 'application/json',
            'Authorization': "Basic " + base64.b64encode(self.opts['email'] + ":" + self.opts['api_key'])
        }
        res = self.sf.fetchUrl("https://api.dehashed.com/search?query=\"" + qry + "\"",
                                headers=headers,
                                timeout=15,
                                useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No Dehashed info found for " + qry)
            return None

        # Always always always process external data with try/except since we cannot
        # trust the data is as intended.
        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from Dehashed.", False)
            return None

        return info

    # Handle events sent to this module
    def handleEvent(self, event):
        # The three most used fields in SpiderFootEvent are:
        # event.eventType - the event type, e.g. INTERNET_NAME, IP_ADDRESS, etc.
        # event.module - the name of the module that generated the event, e.g. sfp_dnsresolve
        # event.data - the actual data, e.g. 127.0.0.1. This can sometimes be megabytes in size (e.g. a PDF)
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return None

        # Log this before complaining about a missing API key so we know the
        # event was received.
        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key'] == "" or self.opts['email'] == "":
            self.sf.error("You enabled sfp_dehashed but did not set an email or API key!", False)
            self.errorState = True
            return None
        

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        entries = list()
        # Fetch Dehashed data for incoming data (email)
        jsonData = self.query(eventData)

        if jsonData is None:
            return None

        entries = jsonData['entries']

        if event.moduleDataSource:
            evt.moduleDataSource = event.moduleDataSource
        else:
            evt.moduleDataSource = "Unknown"

        for entry in entries:
            # If email does not exist or is null
            if entry['email'] is None or str(entry['email']).strip() == '':
                continue
            
            evt = SpiderFootEvent("EMAILADDR_COMPROMISED", entry['email'], self.__name__, event)
            self.notifyListeners(evt)

            # Check if password exists 
            if not entry['password'] is None or str(entry['password']).strip() == '':
                evt = SpiderFootEvent("PASSWORD_COMPROMISED", entry['password'], self.__name__, event)
                self.notifyListeners(evt)

            # Check if hashed_password exists
            if not entry['hashed_password'] is None or str(entry['hashed_password']).strip() == ''
                evt = SpiderFootEvent("HASH_COMPROMISED", entry['hashed_password', self.__name__, event])
                self.notifyListeners(evt)

        if self.checkForStop():
            return None
            
    return None

# End of sfp_dehashed class
