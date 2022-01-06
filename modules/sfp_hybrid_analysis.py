# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_hybrid_analysis
# Purpose:     Search Hybrid Analysis for domains and URLs related to the target.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-08-09
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_hybrid_analysis(SpiderFootPlugin):

    meta = {
        'name': "Hybrid Analysis",
        'summary': "Search Hybrid Analysis for domains and URLs related to the target.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.hybrid-analysis.com",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://www.hybrid-analysis.com/knowledge-base",
                "https://www.hybrid-analysis.com/docs/api/v2"
            ],
            'apiKeyInstructions': [
                "Visit https://www.hybrid-analysis.com/signup",
                "Register a free account",
                "Navigate to https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab",
                "Create an API Key",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://www.hybrid-analysis.com/favicon.ico",
            'logo': "https://www.hybrid-analysis.com/img/logo.svg",
            'description': "A free malware analysis service for the community. "
            "Using this service you can submit files for in-depth static and dynamic analysis.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "verify": True,
        "delay": 1
    }

    # Option descriptions
    optdescs = {
        "api_key": "Hybrid Analysis API key.",
        "verify": "Verify identified domains still resolve to the associated specified IP address.",
        "delay": "Delay between requests, in seconds."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "INTERNET_NAME", "DOMAIN_NAME", "LINKED_URL_INTERNAL"]

    def queryDomain(self, qry):
        """Query a domain

        Args:
            qry (str): domain

        Returns:
            str: API response as JSON
        """

        params = {
            "domain": qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept": "application/json",
            'api-key': self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            'https://www.hybrid-analysis.com/api/v2/search/terms',
            headers=headers,
            timeout=15,
            useragent="Falcon Sandbox",
            postData=params
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def queryHost(self, qry):
        """Query a host

        Args:
            qry (str): host

        Returns:
            str: API response as JSON
        """

        params = {
            "host": qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept": "application/json",
            'api-key': self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            'https://www.hybrid-analysis.com/api/v2/search/terms',
            headers=headers,
            timeout=15,
            useragent="Falcon Sandbox",
            postData=params
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def queryHash(self, qry):
        """Query a hash

        Args:
            qry (str): hash

        Returns:
            str: API response as JSON
        """

        params = {
            "hash": qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept": "application/json",
            'api-key': self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            'https://www.hybrid-analysis.com/api/v2/search/hash',
            headers=headers,
            timeout=15,
            useragent="Falcon Sandbox",
            postData=params
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        """Parse HTTP response from API

        Args:
            res (dict): HTTP response from SpiderFoot.fetchUrl()

        Returns:
            str: API response as JSON
        """

        if res['code'] == '400':
            self.error("Failed to retrieve content from Hybrid Analysis: Invalid request")
            self.debug(f"API response: {res['content']}")
            return None

        # Future proofing - Hybrid Analysis does not implement rate limiting
        if res['code'] == '429':
            self.error("Failed to retrieve content from Hybrid Analysis: rate limit exceeded")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error(f"Failed to retrieve content from Hybrid Analysis: Unexpected response status {res['code']}")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName not in ["IP_ADDRESS", "DOMAIN_NAME"]:
            return

        if eventName == "IP_ADDRESS":
            data = self.queryHost(eventData)
        elif eventName == "DOMAIN_NAME":
            data = self.queryDomain(eventData)
        else:
            return

        if data is None:
            self.debug(f"No information found for{eventData}")
            return

        results = data.get("result")

        if not results:
            return

        hashes = []

        for result in results:
            file_hash = result.get('sha256')
            if file_hash:
                hashes.append(file_hash)

        if not hashes:
            return

        self.info(f"Found {len(hashes)} results for {eventData}")

        evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(evt)

        urls = []
        domains = []

        for file_hash in hashes:
            results = self.queryHash(file_hash)

            if not results:
                self.debug(f"No information found for hash {file_hash}")
                continue

            evt = SpiderFootEvent('RAW_RIR_DATA', str(results), self.__name__, event)
            self.notifyListeners(evt)

            for result in results:
                if not result:
                    continue

                result_domains = result.get('domains')
                if result_domains:
                    for r in result_domains:
                        domains.append(r)

                submissions = result.get('submissions')
                if submissions:
                    for submission in submissions:
                        url = submission.get('url')
                        if url:
                            urls.append(url)

        for url in set(urls):
            host = self.sf.urlFQDN(url.lower())

            if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                continue

            domains.append(host)

            evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
            self.notifyListeners(evt)

        for domain in set(domains):
            if self.checkForStop():
                return

            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                self.debug(f"Host {domain} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_hybrid_analysis class
