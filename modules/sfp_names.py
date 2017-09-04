# coding: utf-8
# -------------------------------------------------------------------------------
# Name:         sfp_names
# Purpose:      Identify human names in content fetched.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     24/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_names(SpiderFootPlugin):
    """Name Extractor:Footprint,Passive:Real World:errorprone:Attempt to identify human names in fetched content."""



    # Default options
    opts = {
        'algotune': 50,
        'emailtoname': True
    }

    # Option descriptions
    optdescs = {
        'algotune': "A value between 0-100 to tune the sensitivity of the name finder. Less than 40 will give you a lot of junk, over 50 and you'll probably miss things but will have less false positives.",
        'emailtoname': "Convert e-mail addresses in the form of firstname.surname@target to names?"
    }

    results = dict()
    d = None
    n = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        d = self.sf.dictwords()
        self.n = self.sf.dictnames()
        # Take dictionary words out of the names list to keep things clean
        self.d = set(set(d) - set(self.n))

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "EMAILADDR", 
                "DOMAIN_WHOIS", "NETBLOCK_WHOIS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["HUMAN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "EMAILADDR" and self.opts['emailtoname']:
            if "." in eventData.split("@")[0]:
                if type(eventData) == unicode:
                    name = " ".join(map(unicode.capitalize, eventData.split("@")[0].split(".")))
                else:
                    name = " ".join(map(str.capitalize, eventData.split("@")[0].split(".")))
                    name = unicode(name, 'utf-8', errors='replace')
                # Notify other modules of what you've found
                evt = SpiderFootEvent("HUMAN_NAME", name, self.__name__, event)
                if event.moduleDataSource:
                    evt.moduleDataSource = event.moduleDataSource
                else:
                    evt.moduleDataSource = "Unknown"
                self.notifyListeners(evt)
                return None

        # Stage 1: Find things that look (very vaguely) like names
        rx = re.compile("([A-Z][a-z�������������]+)\s+.?.?\s?([A-Z][�������������a-zA-Z\'\-]+)")
        m = re.findall(rx, eventData)
        for r in m:
            # Start off each match as 0 points.
            p = 0
            notindict = False

            # Shouldn't encounter "Firstname's Secondname"
            first = r[0].lower()
            if first[len(first) - 2] == "'" or first[len(first) - 1] == "'":
                continue

            # Strip off trailing ' or 's
            secondOrig = r[1].replace("'s", "")
            secondOrig = secondOrig.rstrip("'")
            second = r[1].lower().replace("'s", "")
            second = second.rstrip("'")

            # If both words are not in the dictionary, add 75 points.
            if first not in self.d and second not in self.d:
                p += 75
                notindict = True

            # If the first word is a known popular first name, award 50 points.
            if first in self.n:
                p += 50

            # If either word is 2 characters, subtract 50 points.
            if len(first) == 2 or len(second) == 2:
                p -= 50

            # If the first word is in the dictionary but the second isn't,
            # subtract 40 points.
            if not notindict:
                if first in self.d and second not in self.d:
                    p -= 20

                # If the second word is in the dictionary but the first isn't,
                # reduce 20 points.
                if first not in self.d and second in self.d:
                    p -= 40

            name = r[0] + " " + secondOrig

            if p > self.opts['algotune']:
                # Notify other modules of what you've found
                evt = SpiderFootEvent("HUMAN_NAME", name, self.__name__, event)
                if event.moduleDataSource:
                    evt.moduleDataSource = event.moduleDataSource
                else:
                    evt.moduleDataSource = "Unknown"
                self.notifyListeners(evt)


# End of sfp_names class
