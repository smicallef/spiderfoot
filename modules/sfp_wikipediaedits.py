# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_wikipediaedits
# Purpose:     Identify edits to Wikipedia articles made from a given IP address
#              or username.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     10/09/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_wikipediaedits(SpiderFootPlugin):

    meta = {
        'name': "Wikipedia Edits",
        'summary': "Identify edits to Wikipedia articles made from a given IP address or username.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://www.wikipedia.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.mediawiki.org/wiki/API:Tutorial",
                "https://www.mediawiki.org/wiki/How_to_contribute",
                "https://www.mediawiki.org/wiki/API:Main_page"
            ],
            'favIcon': "https://www.wikipedia.org/static/favicon/wikipedia.ico",
            'logo': "https://www.wikipedia.org/static/apple-touch/wikipedia.png",
            'description': "Wikipedia is a multilingual online encyclopedia created and maintained as an "
            "open collaboration project by a community of volunteer editors, using a wiki-based editing system.",
        }
    }

    opts = {
        "days_limit": "365"
    }

    optdescs = {
        "days_limit": "Maximum age of data to be considered valid (0 = unlimited)."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Wikipedia"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "USERNAME"]

    def producedEvents(self):
        return ["WIKIPEDIA_PAGE_EDIT"]

    def query(self, qry):
        params = {
            "action": "feedcontributions",
            "user": qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        if self.opts['days_limit'] != "0":
            dt = datetime.datetime.now() - datetime.timedelta(days=int(self.opts['days_limit']))
            params["year"] = dt.strftime("%Y")
            params["month"] = dt.strftime("%m")

        res = self.sf.fetchUrl(
            f"https://en.wikipedia.org/w/api.php?{urllib.parse.urlencode(params)}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        if res['code'] in ["404", "403", "500"]:
            self.debug(f"Unexpected response code {res['code']} from Wikipedia")
            return None

        if not res['content']:
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
            return set(links)
        except Exception as e:
            self.error(f"Error processing response from Wikipedia: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)

        if data is None:
            self.debug(f"No results from Wikipedia for {eventData}")
            return

        for link in data:
            evt = SpiderFootEvent("WIKIPEDIA_PAGE_EDIT", link, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_wikipediaedits class
