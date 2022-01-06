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
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://itunes.apple.com/",
            'model': "FREE_AUTH_UNLIMITED",
            'favIcon': "https://itunes.apple.com/favicon.ico",
            'logo': "https://itunes.apple.com/favicon.ico",
            'description': "The Apple iTunes store is a store for downloading "
                "and purchasing apps for Apple devices.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

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
            'RAW_RIR_DATA'
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
            self.debug(f"Error processing JSON response from Apple iTunes: {e}")
            return None

        results = data.get('results')

        if not results:
            self.debug(f"No results found for {qry}")
            return None

        return results

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName not in self.watchedEvents():
            return

        self.results[eventData] = True

        domain_reversed = '.'.join(list(reversed(eventData.lower().split('.'))))
        data = self.query(domain_reversed)

        if not data:
            self.info(f"No results found for {eventData}")
            return

        urls = list()
        hosts = list()
        found = False

        for result in data:
            bundleId = result.get('bundleId')

            if not bundleId:
                continue

            trackName = result.get('trackName')

            if not trackName:
                continue

            version = result.get('version')

            if not version:
                continue

            app_full_name = f"{trackName} {version} ({bundleId})"

            if (
                domain_reversed != bundleId.lower()
                and not bundleId.lower().startswith(f"{domain_reversed}.")
                and not bundleId.lower().endswith(f".{domain_reversed}")
                and f".{domain_reversed}." not in bundleId.lower()
            ):
                self.debug(f"App {app_full_name} does not match {domain_reversed}, skipping")
                continue

            trackViewUrl = result.get('trackViewUrl')

            if not trackViewUrl:
                continue

            app_data = f"{app_full_name}\n<SFURL>{trackViewUrl}</SFURL>"

            evt = SpiderFootEvent('APPSTORE_ENTRY', app_data, self.__name__, event)
            self.notifyListeners(evt)
            found = True

            sellerUrl = result.get('sellerUrl')

            if not sellerUrl:
                continue

            urls.append(sellerUrl)

        for url in set(urls):
            host = self.sf.urlFQDN(url)

            if not host:
                continue

            if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
                self.notifyListeners(evt)
                found = True

            hosts.append(host)

        for host in set(hosts):
            if not host:
                continue

            if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent('AFFILIATE_INTERNET_NAME', host, self.__name__, event)
                self.notifyListeners(evt)
            found = True

        if found:
            evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(data), self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_apple_itunes class
