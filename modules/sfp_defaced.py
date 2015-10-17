# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_defaced
# Purpose:      Checks if a domain or IP appears on the zone-h.org defacement
#               archive.
#
# Author:       steve@binarypool.com
#
# Created:     09/01/2014
# Copyright:   (c) Steve Micallef, 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_defaced(SpiderFootPlugin):
    """Defacement Check:Investigate:Check if an IP or domain appears on the zone-h.org defacement archive."""

    # Default options
    opts = {
        'daysback': 30,
        'checkcohosts': True,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        'daysback': "Ignore defacements older than this many days.",
        'checkcohosts': "Check co-hosted sites?",
        'checkaffiliates': "Check affiliates?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS",
                "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
                "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DEFACED_INTERNET_NAME", "DEFACED_IPADDR",
                "DEFACED_AFFILIATE_INTERNET_NAME",
                "DEFACED_COHOST", "DEFACED_AFFILIATE_IPADDR"]

    def lookupItem(self, target, typeId):
        found = False
        curDate = time.strftime("%Y%m%d")
        url = "http://www.zone-h.org/archive/" + typeId + "=" + target
        res = self.sf.fetchUrl(url, useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.debug("Unable to fetch data from Zone-H for " + target + "(" + typeId + ")")
            return None

        if "<img id='cryptogram' src='/captcha.py'>" in res['content']:
            self.sf.error("CAPTCHA returned from zone-h.org.", False)
            return None

        rx = re.compile("<td>(\d+/\d+/\d+)</td>", re.IGNORECASE | re.DOTALL)
        grps = re.findall(rx, res['content'])
        for m in grps:
            self.sf.debug("Found defaced site: " + target + "(" + typeId + ")")
            found = True
            # Zone-H returns in YYYY/MM/DD
            date = m.replace('/', '')
            if int(date) < int(curDate) - 30:
                self.sf.debug("Defaced site found but too old: " + date)
                found = False
                continue

            if found:
                return url

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None
        else:
            self.results.append(eventData)

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return None
        if eventName == 'AFFILIATE_INTERNET_NAME' or eventName == 'AFFILIATE_IPADDR' \
                and not self.opts['checkaffiliates']:
            return None

        evtType = 'DEFACED_INTERNET_NAME'
        typeId = 'domain'

        if eventName == 'IP_ADDRESS':
            evtType = 'DEFACED_IPADDR'
            typeId = 'ip'

        if eventName == 'CO_HOSTED_SITE':
            evtType = 'DEFACED_COHOST'

        if eventName == 'AFFILIATE_INTERNET_NAME':
            evtType = 'DEFACED_AFFILIATE_INTERNET_NAME'

        if eventName == 'AFFILIATE_IPADDR':
            evtType = 'DEFACED_AFFILIATE_IPADDR'
            typeId = 'ip'

        url = self.lookupItem(eventData, typeId)
        if self.checkForStop():
            return None

        # Notify other modules of what you've found
        if url is not None:
            text = eventData + "\n" + url
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_defaced class
