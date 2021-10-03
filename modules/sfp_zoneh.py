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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_zoneh(SpiderFootPlugin):

    meta = {
        'name': "Zone-H Defacement Check",
        'summary': "Check if a hostname/domain appears on the zone-h.org 'special defacements' RSS feed.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://zone-h.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.zone-h.org/archive",
                "https://www.zone-h.org/archive/special=1"
            ],
            'favIcon': "https://zone-h.org/images/logo.gif",
            'logo': "https://zone-h.org/images/logo.gif",
            'description': "Once a defaced website is submitted to Zone-H, it is mirrored on the Zone-H servers. "
            "The website is then moderated by the Zone-H staff to check if the defacement was fake. "
            "Sometimes, the hackers themselves submit their hacked pages to the site.\n"
            "It is an Internet security portal containing original IT security news, digital warfare news, "
            "geopolitics, proprietary and general advisories, analyses, forums, researches. "
            "Zone-H is the largest web intrusions archive. It is published in several languages.",
        }
    }

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

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS",
                "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR", "AFFILIATE_IPV6_ADDRESS",
                "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DEFACED_INTERNET_NAME", "DEFACED_IPADDR",
                "DEFACED_AFFILIATE_INTERNET_NAME",
                "DEFACED_COHOST", "DEFACED_AFFILIATE_IPADDR"]

    def lookupItem(self, target, content):
        grps = re.findall(r"<title><\!\[CDATA\[(.[^\]]*)\]\]></title>\s+<link><\!\[CDATA\[(.[^\]]*)\]\]></link>", content)
        for m in grps:
            if target in m[0]:
                self.info("Found zoneh site: " + m[0])
                return m[0] + "\n<SFURL>" + m[1] + "</SFURL>"

        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'INTERNET_NAME':
            evtType = 'DEFACED_INTERNET_NAME'
        elif eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            evtType = 'DEFACED_IPADDR'
        elif eventName == 'CO_HOSTED_SITE':
            evtType = 'DEFACED_COHOST'
        elif eventName == 'AFFILIATE_INTERNET_NAME':
            evtType = 'DEFACED_AFFILIATE_INTERNET_NAME'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            evtType = 'DEFACED_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")

        if self.checkForStop():
            return

        url = "https://www.zone-h.org/rss/specialdefacements"
        content = self.sf.cacheGet("sfzoneh", 48)
        if content is None:
            data = self.sf.fetchUrl(url, useragent=self.opts['_useragent'])
            if data['content'] is None:
                self.error("Unable to fetch " + url)
                self.errorState = True
                return

            self.sf.cachePut("sfzoneh", data['content'])
            content = data['content']

        ret = self.lookupItem(eventData, content)
        if ret:
            evt = SpiderFootEvent(evtType, ret, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_zoneh class
