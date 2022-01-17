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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_names(SpiderFootPlugin):

    meta = {
        'name': "Human Name Extractor",
        'summary': "Attempt to identify human names in fetched content.",
        'flags': ["errorprone"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
        'algolimit': 75,
        'emailtoname': True,
        'filterjscss': True
    }

    # Option descriptions
    optdescs = {
        'algolimit': "A value between 0-100 to tune the sensitivity of the name finder. Less than 40 will give you a lot of junk, over 50 and you'll probably miss things but will have less false positives.",
        'emailtoname': "Convert e-mail addresses in the form of firstname.surname@target to names?",
        'filterjscss': "Filter out names that originated from CSS/JS content. Enabling this avoids detection of popular Javascript and web framework author names."
    }

    results = None
    d = None
    n = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.d = set(self.sf.dictwords())
        self.n = set(self.sf.dictnames())

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "EMAILADDR",
                "DOMAIN_WHOIS", "NETBLOCK_WHOIS",
                "RAW_RIR_DATA", "RAW_FILE_META_DATA"]

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

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # If the source event is web content, check if the source URL was javascript
        # or CSS, in which case optionally ignore it.
        if eventName == "TARGET_WEB_CONTENT":
            url = event.actualSource
            if url is not None:
                if self.opts['filterjscss'] and (".js" in url or ".css" in url):
                    self.debug("Ignoring web content from CSS/JS.")
                    return

        # Find names in email addresses in "<firstname>.<lastname>@<domain>" format
        if eventName == "EMAILADDR" and self.opts['emailtoname']:
            potential_name = eventData.split("@")[0]

            if "." not in potential_name:
                return

            name = " ".join(map(str.capitalize, potential_name.split(".")))

            # Names usually do not contain numbers
            if re.search("[0-9]", name):
                return

            evt = SpiderFootEvent("HUMAN_NAME", name, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)
            return

        # For RAW_RIR_DATA, there are only specific modules we
        # expect to see RELEVANT names within.
        if eventName == "RAW_RIR_DATA":
            if srcModuleName not in ["sfp_arin", "sfp_builtwith", "sfp_clearbit",
                                     "sfp_fullcontact", "sfp_github", "sfp_hunter",
                                     "sfp_opencorporates", "sfp_slideshare",
                                     "sfp_twitter", "sfp_venmo", "sfp_instagram",
                                     "sfp_stackoverflow"]:
                self.debug("Ignoring RAW_RIR_DATA from untrusted module.")
                return

        # Stage 1: Find things that look (very vaguely) like names
        rx = re.compile(r"([A-Z][a-z�������������]+)\s+.?.?\s?([A-Z][�������������a-zA-Z\'\-]+)")
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
                self.debug(f"Both first and second names are not in the dictionary, so high chance of name: ({first}:{second}).")
                p += 75
                notindict = True
            else:
                self.debug(first + " was found or " + second + " was found in dictionary.")

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

            self.debug("Name of " + name + " has score: " + str(p))
            if p >= self.opts['algolimit']:
                # Notify other modules of what you've found
                evt = SpiderFootEvent("HUMAN_NAME", name, self.__name__, event)
                if event.moduleDataSource:
                    evt.moduleDataSource = event.moduleDataSource
                else:
                    evt.moduleDataSource = "Unknown"
                self.notifyListeners(evt)


# End of sfp_names class
