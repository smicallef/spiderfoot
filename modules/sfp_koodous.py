# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_koodous
# Purpose:     Query Koodous for mobile apps.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-09-19
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_koodous(SpiderFootPlugin):

    meta = {
        'name': "Koodous",
        'summary': "Search Koodous for mobile apps.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.koodous.com/rest-api/apks/",
            ],
            'website': "https://koodous.com/apks/",
            'logo': "https://koodous.com/assets/img/koodous-logo.png",
        }
    }

    opts = {
        'max_pages': 10,
    }

    optdescs = {
        'max_pages': "Maximum number of pages of results to fetch.",
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
        ]

    def queryPackageName(self, qry, cursor=''):
        package_name = qry.encode('raw_unicode_escape').decode("ascii", errors='replace')

        params = urllib.parse.urlencode({
            'cursor': cursor,
            'search': f"package_name:*{package_name}.*"
        })

        res = self.sf.fetchUrl(
            f"https://api.koodous.com/apks?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        time.sleep(1)

        if res['content'] is None:
            return None

        if res['code'] != '200':
            self.error(f"Unexpected reply from Koodous: {res['code']}")
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from Koodous: {e}")
            return None

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName not in self.watchedEvents():
            return

        self.results[eventData] = True

        domain_reversed = '.'.join(list(reversed(eventData.lower().split('.'))))

        max_pages = int(self.opts['max_pages'])
        page = 1
        cursor = ''
        found = False
        while page <= max_pages:
            if self.checkForStop():
                return

            data = self.queryPackageName(domain_reversed, cursor)

            page += 1

            if not data:
                self.errorState = True
                return

            results = data.get('results')

            for result in results:
                package_name = result.get('package_name')

                if not package_name:
                    continue

                app = result.get('app')

                if not app:
                    continue

                displayed_version = result.get('displayed_version')

                if not displayed_version:
                    continue

                app_full_name = f"{app} {displayed_version} ({package_name})"

                if (
                    domain_reversed != package_name.lower()
                    and not package_name.lower().startswith(f"{domain_reversed}.")
                    and not package_name.lower().endswith(f".{domain_reversed}")
                    and f".{domain_reversed}." not in package_name.lower()
                ):
                    self.debug(f"App {app_full_name} does not match {domain_reversed}, skipping")
                    continue

                sha256 = result.get('sha256')

                if not sha256:
                    continue

                app_data = f"{app_full_name}\n<SFURL>https://koodous.com/apks/{sha256}</SFURL>"

                evt = SpiderFootEvent('APPSTORE_ENTRY', app_data, self.__name__, event)
                self.notifyListeners(evt)
                found = True

            if found:
                evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(data), self.__name__, event)
                self.notifyListeners(evt)

            if not data.get('next'):
                break

            next_cursor = re.findall('cursor=(.+?)&', data.get('next'))
            if not next_cursor:
                break

            cursor = urllib.parse.unquote(next_cursor[0])

# End of sfp_koodous class
