# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_apple_itunes
# Purpose:     Query Apple iTunes for mobile apps.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-09-19
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_apple_itunes(SpiderFootPlugin):

    meta = {
        'name': "Apple iTunes",
        'summary': "Search Apple iTunes for mobile apps.",
        'flags': [""],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://itunes.apple.com/",
            'favIcon': "https://itunes.apple.com/favicon.ico",
            'logo': "https://itunes.apple.com/favicon.ico",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'DOMAIN_NAME'
        ]

    def producedEvents(self):
        return [
            'APPSTORE_ENTRY',
            'INTERNET_NAME',
            'LINKED_URL_INTERNAL',
            'AFFILIATE_INTERNET_NAME',
        ]

    def query(self, qry, limit=100):
        params = urllib.parse.urlencode({
            'media': 'software',
            'entity': 'software,iPadSoftware,softwareDeveloper',
            'limit': limit,
            'term': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        })

        res = self.sf.fetchUrl(
            f"https://itunes.apple.com/search?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug(f"Error processing JSON response from Apple iTunes: {e}")
            return None

        results = data.get('results')

        if not results:
            self.sf.debug(f"No results found for {qry}")
            return None

        return results

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName not in self.watchedEvents():
            return

        self.results[eventData] = True

        domain_reversed = '.'.join(list(reversed(eventData.split('.'))))
        data = self.query(domain_reversed)

        if not data:
            self.sf.info(f"No results found for {eventData}")
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(data), self.__name__, event)
        self.notifyListeners(evt)

        urls = list()

        for result in data:
            bundleId = result.get('bundleId')
            trackName = result.get('trackName')
            trackViewUrl = result.get('trackViewUrl')
            version = result.get('version')

            if not bundleId:
                continue

            app_full_name = f"{trackName} {version} ({bundleId})"

            if not bundleId.startswith(f"{domain_reversed}.") and f".{domain_reversed}." not in bundleId:
                self.sf.debug(f"App {app_full_name} does not match {domain_reversed}, skipping")
                continue

            trackName = result.get('trackName')
            trackViewUrl = result.get('trackViewUrl')
            version = result.get('version')

            if not trackName and not trackViewUrl and not version:
                continue

            app_data = f"{trackName} {version}\n<SFURL>{trackViewUrl}</SFURL>"

            evt = SpiderFootEvent('APPSTORE_ENTRY', app_data, self.__name__, event)
            self.notifyListeners(evt)

            sellerUrl = result.get('sellerUrl')

            if not sellerUrl:
                continue

            urls.append(sellerUrl)

        for url in set(urls):
            host = self.sf.urlFQDN(url)

            if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
                self.notifyListeners(evt)
                evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent('AFFILIATE_INTERNET_NAME', host, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_apple_itunes class
