# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_badipscom
# Purpose:     Checks if an IP address is malicious according to BadIPs.com.
#
# Author:      steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_badipscom(SpiderFootPlugin):
    """badips.com:Investigate,Passive:Reputation Systems::Check if an IP address is malicious according to BadIPs.com."""


    # Default options
    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliate IP addresses?",
        'cacheperiod': "Hours to cache list data before re-fetching."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR"]

    def query(self, qry):
        cid = "_badips"
        url = "https://www.badips.com/get/list/any/1?age=24h"

        data = dict()
        data["content"] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))

        if data["content"] is None:
            data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if data["code"] != "200":
                self.sf.error("Unable to fetch %s" % url, False)
                self.errorState = True
                return None

            if data["content"] is None:
                self.sf.error("Unable to fetch %s" % url, False)
                self.errorState = True
                return None

            self.sf.cachePut("sfmal_" + cid, data['content'])

        for line in data["content"].split('\n'):
            if qry.lower() == line.lower():
                self.sf.debug("%s found in BadIPS.com IP Reputation List." % (qry))
                return url

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None

        if self.errorState:
            return None

        if eventName not in ['IP_ADDRESS', 'AFFILIATE_IPADDR']:
            return None

        self.results[eventData] = True

        evtType = 'MALICIOUS_IPADDR'

        if eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return None
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'

        self.sf.debug("Checking maliciousness of IP address %s with BadIPs.com" % eventData)

        url = self.query(eventData)

        if not url:
            return None

        text = "BadIPs.com IP Reputation List [%s]\n<SFURL>%s</SFURL>" % (eventData, url)
        evt = SpiderFootEvent(evtType, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_badipscom class
