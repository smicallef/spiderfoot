# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_torch
# Purpose:      Searches the Tor search engine 'TORCH' for content related 
#               to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import re

class sfp_torch(SpiderFootPlugin):
    """TORCH:Footprint,Investigate:Search Engines::Search Tor 'TORCH' search engine for mentions of the target domain."""


    # Default options
    opts = {
        'fetchlinks': False,
        'pages': 20,
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'pages': "Number of results pages to iterate through."
    }

    # Target
    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DARKNET_MENTION_URL", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results.append(eventData)

        formpage = self.sf.fetchUrl("http://xmh57jrzrnw6insl.onion",
                                useragent=self.opts['_useragent'],
                                timeout=self.opts['_fetchtimeout'])

        if not formpage['content']:
            self.sf.info("Couldn't connect to TORCH, check that you have TOR enabled.")
            return None
        else:
            # Need the form ID to submit later for the search
            m = re.findall("\<form method=\"get\" action=\"/(\S+)/search.cgi\"\>", 
                           formpage['content'], re.IGNORECASE | re.DOTALL)
            if not m:
                return None

            formid = m[0]

        pagecontent = ""
        pagecount = 0
        p = ""
        while "color=gray>next &gt;&gt;" not in pagecontent.lower() and pagecount < self.opts['pages']:
            if pagecount > 0:
                p = "&np=" + str(pagecount)
            pagecount += 1

            # Sites hosted on the domain
            data = self.sf.fetchUrl("http://xmh57jrzrnw6insl.onion/" + formid + "/search.cgi?q=" + \
                                    eventData + "&cmd=Search!" + p,
                                    useragent=self.opts['_useragent'],
                                    timeout=self.opts['_fetchtimeout'])
            if data is None or not data.get('content'):
                self.sf.info("No results returned from TORCH.")
                return None

            pagecontent = data['content']

            if "No documents were found" not in data['content']:
                # Check if we've been asked to stop
                if self.checkForStop():
                    return None

                # Submit the google results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", data['content'],
                                      self.__name__, event)
                self.notifyListeners(evt)

                links = re.findall("\<DT\>\d+.\s+<a href=\"(.*?)\"\s+TARGET=\"_blank\"\>",
                                   data['content'], re.IGNORECASE | re.DOTALL)

                for link in links:
                    if link in self.results:
                        continue
                    else:
                        self.results.append(link)
                        self.sf.debug("Found a darknet mention: " + link)
                        if self.sf.urlFQDN(link).endswith(".onion"):
                            if self.checkForStop():
                                return None
                            if self.opts['fetchlinks']:
                                res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                                       useragent=self.opts['_useragent'])
    
                                if res['content'] is None:
                                    self.sf.debug("Ignoring " + link + " as no data returned")
                                    continue
    
                                if eventData not in res['content']:
                                    self.sf.debug("Ignoring " + link + " as no mention of " + eventData)
                                    continue
                                evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                                self.notifyListeners(evt)
                            else:
                                evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                                self.notifyListeners(evt)


# End of sfp_torch class
