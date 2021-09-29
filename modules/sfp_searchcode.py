# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_searchcode
# Purpose:     Search searchcode for code repositories mentioning the target domain.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-07-06
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_searchcode(SpiderFootPlugin):

    meta = {
        'name': "searchcode",
        'summary': "Search searchcode for code repositories mentioning the target domain.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://searchcode.com/api/",
            ],
            'website': "https://searchcode.com/",
            'logo': "https://searchcode.com/static/small_logo.png",
            'description': "Simple, comprehensive code search."
        }
    }

    opts = {
        'max_pages': 10,
        'dns_resolve': True,
    }

    optdescs = {
        'max_pages': "Maximum number of pages of results to fetch.",
        'dns_resolve': "DNS resolve each identified domain.",
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
            'EMAILADDR',
            'EMAILADDR_GENERIC',
            'LINKED_URL_INTERNAL',
            'PUBLIC_CODE_REPO',
            'RAW_RIR_DATA',
        ]

    def query(self, qry, page=1, per_page=100):
        params = urllib.parse.urlencode({
            'q': qry,
            'p': page,
            'per_page': per_page
        })

        res = self.sf.fetchUrl(
            f"https://searchcode.com/api/codesearch_I/?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        time.sleep(2)

        if res['content'] is None:
            return None

        if res['code'] == "429":
            self.error("You are being rate-limited by searchcode.")
            self.errorState = True
            return None

        if res['code'] != '200':
            self.error(f"Unexpected reply from searchcode: {res['code']}")
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from searchcode: {e}")
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

        max_pages = int(self.opts['max_pages'])
        page = 0
        while page < max_pages:
            if self.checkForStop():
                return

            data = self.query(eventData, page)

            page += 1

            if not data:
                self.errorState = True
                return

            results = data.get('results')

            if not results:
                return

            emails = self.sf.parseEmails(str(results))
            for email in emails:
                if email in self.results:
                    continue

                mail_domain = email.lower().split('@')[1]
                if not self.getTarget().matches(mail_domain):
                    self.debug(f"Skipped email address: {email}")
                    continue

                self.info(f"Found e-mail address: {email}")

                evt_type = "EMAILADDR"
                if email.split("@")[0] in self.opts['_genericusers'].split(","):
                    evt_type = "EMAILADDR_GENERIC"
                evt = SpiderFootEvent(evt_type, email, self.__name__, event)
                self.notifyListeners(evt)
                self.results[email] = True

            links = set()
            for result in results:
                lines = result.get('lines')
                if lines:
                    for line in lines:
                        links.update(self.sf.extractUrls(lines[line]))

            for link in links:
                if link in self.results:
                    continue

                host = self.sf.urlFQDN(link)

                if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                    self.debug(f"Skipped unrelated URL: {link}")
                    continue

                self.debug(f"Found a URL: {link}")
                evt = SpiderFootEvent('LINKED_URL_INTERNAL', link, self.__name__, event)
                self.notifyListeners(evt)
                self.results[link] = True

                if host in self.results:
                    continue

                if self.opts['dns_resolve'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                    self.debug(f"Host {host} could not be resolved")
                    evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
                    self.notifyListeners(evt)

                self.results[host] = True

            for result in results:
                if eventData not in str(result):
                    continue

                repo = result.get('repo')

                if not repo:
                    continue

                if repo in self.results:
                    continue

                url = result.get('url')

                if not url:
                    continue

                repo_data = f"{repo}\n<SFURL>{url}</SFURL>"

                evt = SpiderFootEvent('PUBLIC_CODE_REPO', repo_data, self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(result), self.__name__, event)
                self.notifyListeners(evt)

                self.results[repo] = True

            if not data.get('nextpage'):
                break

# End of sfp_searchcode class
