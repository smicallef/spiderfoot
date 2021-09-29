# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_crossref
# Purpose:      SpiderFoot plug-in for scanning links identified from the
#               spidering process, and for external links, fetching them to
#               see if those sites link back to the original site, indicating a
#               potential relationship between the external sites.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_crossref(SpiderFootPlugin):

    meta = {
        'name': "Cross-Referencer",
        'summary': "Identify whether other domains are associated ('Affiliates') of the target by looking for links back to the target site(s).",
        'flags': [],
        'useCases': ["Footprint"],
        'categories': ["Crawling and Scanning"]
    }

    opts = {
        'checkbase': True
    }

    optdescs = {
        "checkbase": "Check the base URL of the potential affiliate if no direct affiliation found?"
    }

    fetched = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.fetched = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'LINKED_URL_EXTERNAL',
            'SIMILARDOMAIN',
            'CO_HOSTED_SITE',
            'DARKNET_MENTION_URL'
        ]

    def producedEvents(self):
        return [
            'AFFILIATE_INTERNET_NAME',
            'AFFILIATE_WEB_CONTENT'
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # SIMILARDOMAIN and CO_HOSTED_SITE events are domains, not URLs.
        # Assume HTTP.
        if eventName in ['SIMILARDOMAIN', 'CO_HOSTED_SITE']:
            url = 'http://' + eventData.lower()
        elif 'URL' in eventName:
            url = eventData
        else:
            return

        fqdn = self.sf.urlFQDN(url)

        # We are only interested in external sites for the crossref
        if self.getTarget().matches(fqdn):
            self.debug(f"Ignoring {url} as not external")
            return

        if eventData in self.fetched:
            self.debug(f"Ignoring {url} as already tested")
            return

        if not self.sf.resolveHost(fqdn) and not self.sf.resolveHost6(fqdn):
            self.debug(f"Ignoring {url} as {fqdn} does not resolve")
            return

        self.fetched[url] = True

        self.debug(f"Testing URL for affiliation: {url}")

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            sizeLimit=10000000,
            verify=False
        )

        if res['content'] is None:
            self.debug(f"Ignoring {url} as no data returned")
            return

        matched = False
        for name in self.getTarget().getNames():
            # Search for mentions of our host/domain in the external site's data
            pat = re.compile(
                r"([\.\'\/\"\ ]" + re.escape(name) + r"[\.\'\/\"\ ])",
                re.IGNORECASE
            )
            matches = re.findall(pat, str(res['content']))

            if len(matches) > 0:
                matched = True
                break

        if not matched:
            # If the name wasn't found in the affiliate, and checkbase is set,
            # fetch the base URL of the affiliate to check for a crossref.
            if eventName == "LINKED_URL_EXTERNAL" and self.opts['checkbase']:
                # Check the base url to see if there is an affiliation
                url = self.sf.urlBaseUrl(eventData)
                if url in self.fetched:
                    return

                self.fetched[url] = True

                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['_fetchtimeout'],
                    useragent=self.opts['_useragent'],
                    sizeLimit=10000000,
                    verify=False
                )

                if res['content'] is not None:
                    for name in self.getTarget().getNames():
                        pat = re.compile(
                            r"([\.\'\/\"\ ]" + re.escape(name) + r"[\'\/\"\ ])",
                            re.IGNORECASE
                        )
                        matches = re.findall(pat, str(res['content']))

                        if len(matches) > 0:
                            matched = True
                            break

        if not matched:
            return

        if not event.moduleDataSource:
            event.moduleDataSource = "Unknown"

        self.info(f"Found link to target from affiliate: {url}")

        evt1 = SpiderFootEvent(
            "AFFILIATE_INTERNET_NAME",
            self.sf.urlFQDN(url),
            self.__name__,
            event
        )
        evt1.moduleDataSource = event.moduleDataSource
        self.notifyListeners(evt1)

        evt2 = SpiderFootEvent(
            "AFFILIATE_WEB_CONTENT",
            res['content'],
            self.__name__,
            evt1
        )
        evt2.moduleDataSource = event.moduleDataSource
        self.notifyListeners(evt2)

# End of sfp_crossref class
