# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ripe
# Purpose:      Query the RIPE REST API to find the person who registered the IP address
#
# Author:      Nander Hokwerda <nander@hackershub.co>
#
# Created:     7/11/2015
# Copyright:   (c) Nander Hokwerda
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import sys
import urllib2
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_ripe(SpiderFootPlugin):
    """RIPE Person Scan:Scan for person names:Get the person who registered the IP addresses"""

    # Default options
    opts = {
        "restapiurl": "http://rest.db.ripe.net/search?query-string="
    }

    # Option descriptions
    optdescs = {
        "restapiurl": "The url for the RIPE REST API"
    }

    results = dict()


    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["HUMAN_NAME", "PHONENR"]

    def query(self, qry):
        try:
            self.sf.info("[+] Starting query for: " + qry)

            #Build the url based on the option and query address
            restUrl = self.opts['restapiurl']
            fullUrl = restUrl + qry

            #Create a new request for the url and add the header so json is returned
            req = urllib2.Request(fullUrl)
            req.add_header('accept','application/json')

            #Open the url and parse content as json
            resp = urllib2.urlopen(req)
            content = resp.read()
            jsonContent = json.loads(content)

            #init the variables
            personName = None
            phoneNr = None

            #Loop through the returned objects
            for object in jsonContent['objects']['object']:
                #If there is an object with type person look for attribute person and return its value
                if object['type'] == "person":
                    for attribute in object['attributes']['attribute']:
                        if attribute['name'] == "person":
                            personName = attribute['value']
                        if attribute['name'] == "phone":
                            phoneNr = attribute['value']

            #return the variables
            return personName, phoneNr

        except Exception, e:
            self.sf.info("[+] Caught error while executing query for: " + qry + " - " + str(e))
            return None


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

            # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        qrylist = list()

        qrylist.append(eventData)

        for addr in qrylist:
            personName, phoneNr = self.query(addr)
            if personName is None and phoneNr is None:
                continue

            if self.checkForStop():
                return None

            if personName is not None:
                # Notify other modules of what you've found
                self.sf.info("Found RIPE Owner for " + eventData)
                evt = SpiderFootEvent("HUMAN_NAME", personName , self.__name__, event)
                self.notifyListeners(evt)

            if phoneNr is not None:
                # Notify other modules of what you've found
                self.sf.info("Found phone number for RIPE Owner for " + eventData)
                evt = SpiderFootEvent("PHONENR", phoneNr , self.__name__, event)
                self.notifyListeners(evt)



        return None

# End of sfp_ripe class
