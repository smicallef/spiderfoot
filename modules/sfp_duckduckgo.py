# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_duckduckgo
# Purpose:      Queries DuckDuckGo's API for information abotut the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_duckduckgo(SpiderFootPlugin):

    meta = {
        'name': "DuckDuckGo",
        'summary': "Query DuckDuckGo's API for descriptive information about your target.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://duckduckgo.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://api.duckduckgo.com/api",
                "https://help.duckduckgo.com/company/partnerships/",
                "https://help.duckduckgo.com/duckduckgo-help-pages/"
            ],
            'favIcon': "https://duckduckgo.com/favicon.ico",
            'logo': "https://duckduckgo.com/assets/icons/meta/DDG-icon_256x256.png",
            'description': "Our Instant Answer API gives you free access to many of our instant answers like: "
            "topic summaries , categories, disambiguation, and !bang redirects.",
        }
    }

    # Default options
    opts = {
        "affiliatedomains": True
    }

    # Option descriptions
    optdescs = {
        "affiliatedomains": "For affiliates, look up the domain name, not the hostname. This will usually return more meaningful information about the affiliate."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT",
                "INTERNET_NAME", "AFFILIATE_INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DESCRIPTION_CATEGORY", "DESCRIPTION_ABSTRACT",
                "AFFILIATE_DESCRIPTION_CATEGORY",
                "AFFILIATE_DESCRIPTION_ABSTRACT"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.opts['affiliatedomains'] and "AFFILIATE_" in eventName:
            eventData = self.sf.hostDomain(eventData, self.opts['_internettlds'])
            if not eventData:
                return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        url = "https://api.duckduckgo.com/?q=" + eventData + "&format=json&pretty=1"
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot")

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            return

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from DuckDuckGo: {e}")
            return

        if not ret['Heading']:
            self.debug(f"No DuckDuckGo information for {eventData}")
            return

        # Submit the DuckDuckGo results for analysis
        evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", res['content'],
                              self.__name__, event)
        self.notifyListeners(evt)

        abstract_text = ret.get('AbstractText')
        if abstract_text:
            event_type = "DESCRIPTION_ABSTRACT"

            if "AFFILIATE" in eventName:
                event_type = "AFFILIATE_" + event_type

            evt = SpiderFootEvent(event_type, str(abstract_text), self.__name__, event)
            self.notifyListeners(evt)

        related_topics = ret.get('RelatedTopics')
        if related_topics:
            event_type = "DESCRIPTION_CATEGORY"

            if "AFFILIATE" in eventName:
                event_type = "AFFILIATE_" + event_type

            for topic in related_topics:
                if not isinstance(topic, dict):
                    self.debug("No category text found from DuckDuckGo.")
                    continue

                category = topic.get('Text')

                if not category:
                    self.debug("No category text found from DuckDuckGo.")
                    continue

                evt = SpiderFootEvent(event_type, category, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_duckduckgo class
