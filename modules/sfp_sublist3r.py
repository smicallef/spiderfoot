# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sublist3r
# Purpose:      Query Sublist3r using their API
#
# Author:      Steve Micallef
#
# Created:     16/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_sublist3r(SpiderFootPlugin):
    """Sublist3r:Investigate,Passive,Footprint:Search Engines::Obtain information from Sublist3r's database of hostnames."""


    # Default options
    opts = {
        "verify": True
    }

    # Option descriptions
    optdescs = {
        "verify": "Verify hosts still resolve?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Verify a host resolves
    def resolveHost(self, host):
        try:
            # IDNA-encode the hostname in case it contains unicode
            if type(host) != unicode:
                host = unicode(host, "utf-8", errors='replace').encode("idna")
            else:
                host = host.encode("idna")

            addrs = socket.gethostbyname_ex(host)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

        return True

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def query(self, qry):
        url = "https://api.sublist3r.com/search.php?domain=" + qry

        # Be more forgiving with the timeout as some queries for subnets can be slow
        res = self.sf.fetchUrl(url , timeout=30, useragent="SpiderFoot")

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("Sublist3r access seems to have been rejected or you have exceeded usage limits.", False)
            return None

        if res['content'] is None:
            self.sf.info("No Sublist3r info found for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except BaseException as e:
            self.sf.error("Invalid JSON returned by Sublist3r.", False)
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        ret = None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        ret = self.query(eventData)
        if ret:
            for res in ret:
                if self.opts['verify']:
                    if not self.resolveHost(res):
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", res, self.__name__, event)
                        self.notifyListeners(e)
                        continue

                e = SpiderFootEvent("INTERNET_NAME", res, self.__name__, event)
                self.notifyListeners(e)

# End of sfp_sublist3r class
