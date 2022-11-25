# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_koodous
# Purpose:     Query Koodous for mobile apps.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-09-19
# Copyright:   (c) bcoles 2019
# Licence:     MIT
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
        'flags': ["apikey"],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'model': "FREE_AUTH_LIMITED",
            "apiKeyInstructions": [
                "Visit https://koodous.com/apks",
                "Register a free account",
                "Visit https://koodous.com/settings/developers and use the authentication token provided",
            ],
            'references': [
                "https://docs.koodous.com/api/apks.html",
                "https://docs.koodous.com/apks.html#apks-search-system"
            ],
            'website': "https://koodous.com/apks/",
            'favIcon': "https://koodous.com/favicon.ico",
            'logo': "https://koodous.com/assets/img/koodous-logo.png",
            "description": "The Collaborative Platform for Android Malware Analysts."
        }
    }

    opts = {
        "api_key": "",
        'max_pages': 10,
    }

    optdescs = {
        "api_key": "Koodous API key.",
        'max_pages': "Maximum number of pages of results to fetch.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
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
            'RAW_RIR_DATA'
        ]

    def queryPackageName(self, qry, cursor=''):
        package_name = qry.encode('raw_unicode_escape').decode("ascii", errors='replace')

        params = urllib.parse.urlencode({
            'cursor': cursor,
            'search': f"package:{package_name}.*"
        })

        res = self.sf.fetchUrl(
            f"https://developer.koodous.com/apks/?{params}",
            headers={"Authorization": f"Token {self.opts['api_key']}"},
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        # 100 requests per minute
        time.sleep(1)

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from Koodous.")
            return None

        if res['code'] == '404':
            self.debug("No results from Koodous.")
            return None

        if res['code'] == "401":
            self.error("Invalid Koodous API key.")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by Koodous.")
            self.errorState = True
            return None

        if res['code'] == '500' or res['code'] == '502' or res['code'] == '503':
            self.error("Koodous service is unavailable")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error(f"Unexpected reply from Koodous: {res['code']}")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from Koodous: {e}")

        return None

    def handleEvent(self, event):
        if self.errorState:
            return

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Reverse domain name to create potential package name
        domain_reversed = '.'.join(list(reversed(eventData.lower().split('.'))))

        max_pages = int(self.opts['max_pages'])
        page = 1
        cursor = ''
        while page <= max_pages:
            found = False

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

                # results can have a null app name, but it is probably a duplicate
                if not app:
                    continue

                # TODO: compare company name with target
                # company = result.get('company')

                version = result.get('version')

                if version:
                    app_full_name = f"{app} {version} ({package_name})"
                else:
                    app_full_name = f"{app} ({package_name})"

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
