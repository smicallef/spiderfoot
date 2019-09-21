# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_zoneh
# Purpose:      Checks if a domain or IP appears on the zone-h.org defacement
#               archive.
#
# Author:       steve@binarypool.com
#
# Created:     09/01/2014
# Copyright:   (c) Steve Micallef, 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_zoneh(SpiderFootPlugin):
    """Zone-H Defacement Check:Investigate,Passive:Leaks, Dumps and Breaches::Check if a hostname/domain appears on the zone-h.org 'special defacements' RSS feed."""


    # Default options
    opts = {
        'checkcohosts': True,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        'checkcohosts': "Check co-hosted sites?",
        'checkaffiliates': "Check affiliates?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False

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

    def lookupItem(self, target, content):
        grps = re.findall("<title><\!\[CDATA\[(.[^\]]*)\]\]></title>\s+<link><\!\[CDATA\[(.[^\]]*)\]\]></link>", content)
        for m in grps:
            if target in m[0]:
                self.sf.info("Found zoneh site: " + m[0])
                return m[0] + "\n<SFURL>" + m[1] + "</SFURL>"

        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.errorState:
            return None

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None
        else:
            self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return None
        if eventName == 'AFFILIATE_INTERNET_NAME' or eventName == 'AFFILIATE_IPADDR' \
                and not self.opts['checkaffiliates']:
            return None

        evtType = 'DEFACED_INTERNET_NAME'

        if eventName == 'IP_ADDRESS':
            evtType = 'DEFACED_IPADDR'

        if eventName == 'CO_HOSTED_SITE':
            evtType = 'DEFACED_COHOST'

        if eventName == 'AFFILIATE_INTERNET_NAME':
            evtType = 'DEFACED_AFFILIATE_INTERNET_NAME'

        if eventName == 'AFFILIATE_IPADDR':
            evtType = 'DEFACED_AFFILIATE_IPADDR'

        if self.checkForStop():
            return None

        url = "https://www.zone-h.org/rss/specialdefacements"
        content = self.sf.cacheGet("sfzoneh", 48)
        if content is None:
            data = self.sf.fetchUrl(url, useragent=self.opts['_useragent'])
            if data['content'] is None:
                self.sf.error("Unable to fetch " + url, False)
                self.errorState = True
                return None
            else:
                self.sf.cachePut("sfzoneh", data['content'])
                content = data['content']

        ret = self.lookupItem(eventData, content)
        if ret:
            evt = SpiderFootEvent(evtType, ret, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_zoneh class
