#-------------------------------------------------------------------------------
# Name:         sfp_wikipediaedits
# Purpose:      Identify edits to Wikipedia articles made from a given IP address
#               or username.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     10/09/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import datetime
import re
from HTMLParser import HTMLParser
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_wikipediaedits(SpiderFootPlugin):
    """Wikipedia Edits:Footprint,Investigate,Passive:Secondary Networks::Identify edits to Wikipedia articles made from a given IP address or username."""


    # Default options
    opts = { 
        "days_limit": "365"
    }

    # Option descriptions
    optdescs = {
        "days_limit": "Maximum age of data to be considered valid (0 = unlimited)."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "Wikipedia"

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "USERNAME"]

    # What events this module produces
    def producedEvents(self):
        return ["WIKIPEDIA_PAGE_EDIT"]

    def query(self, qry):
        url = "https://en.wikipedia.org/w/api.php?action=feedcontributions&user=" + qry
        if self.opts['days_limit'] != "0":
            dt = datetime.datetime.now() - datetime.timedelta(days=int(self.opts['days_limit']))
            y = dt.strftime("%Y")
            m = dt.strftime("%m")
            url += "&year=" + y + "&month=" + m
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot")
        if res['code'] in [ "404", "403", "500" ]:
            return None

        links = list()
        try:
            parser = HTMLParser()
            for line in res['content'].split("\n"):
                matches = re.findall("<link>(.*?)</link>", line, re.IGNORECASE)
                for m in matches:
                    if "Special:Contributions" in m:
                        continue
                    d = parser.unescape(m)
                    links.append(d)
            return links
        except Exception as e:
            self.sf.error("Error processing response from Wikipedia: " + str(e), False)
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

        data = self.query(eventData)
        if data == None:
            return None

        for l in data:
            e = SpiderFootEvent("WIKIPEDIA_PAGE_EDIT", l,
                                self.__name__, event)
            self.notifyListeners(e)

# End of sfp_wikipediaedits class
