# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_mnemonic
# Purpose:     SpiderFoot plug-in for retrieving passive DNS information
#              from Mnemonic PassiveDNS API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-12
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_mnemonic(SpiderFootPlugin):

    meta = {
        'name': "Mnemonic PassiveDNS",
        'summary': "Obtain Passive DNS information from PassiveDNS.mnemonic.no.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://www.mnemonic.no",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.mnemonic.no/resources/whitepapers/",
                "https://www.mnemonic.no/research-and-development/",
                "https://docs.mnemonic.no/display/public/API/PassiveDNS+Integration+Guide"
            ],
            'favIcon': "https://www.mnemonic.no/favicon-96x96.png",
            'logo': "https://www.mnemonic.no/UI/logo.svg",
            'description': "mnemonic helps businesses manage their security risks, "
            "protect their data and defend against cyber threats.\n"
            "Our expert team of security consultants, product specialists, "
            "threat researchers, incident responders and ethical hackers, combined "
            "with our Argus security platform ensures we stay ahead of "
            "advanced cyberattacks and protect our customers from evolving threats.",
        }
    }

    opts = {
        'per_page': 500,
        'max_pages': 2,
        'timeout': 30,
        'maxage': 180,    # 6 months
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    optdescs = {
        'per_page': "Maximum number of results per page.",
        'max_pages': "Maximum number of pages of results to fetch.",
        'timeout': "Query timeout, in seconds.",
        'maxage': "The maximum age of the data returned, in days, in order to be considered valid.",
        'verify': "Verify identified domains still resolve to the associated specified IP address.",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
    }

    cohostcount = 0
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'IPV6_ADDRESS',
            'INTERNET_NAME',
            'DOMAIN_NAME'
        ]

    def producedEvents(self):
        return [
            'IP_ADDRESS',
            'IPV6_ADDRESS',
            'INTERNAL_IP_ADDRESS',
            'CO_HOSTED_SITE',
            'INTERNET_NAME',
            'DOMAIN_NAME'
        ]

    def query(self, qry, limit=500, offset=0):
        """Query the Mnemonic PassiveDNS v3 API.

        Args:
            qry (str): domain name or IP address
            limit (int): Limit the number of returned values.
            offset (int): Skip the initial <offset> number of values in the resultset.

        Returns:
            dict: results as JSON
        """

        params = urllib.parse.urlencode({
            'limit': limit,
            'offset': offset
        })

        res = self.sf.fetchUrl(
            f"https://api.mnemonic.no/pdns/v3/{qry}?{params}",
            timeout=self.opts['timeout'],
            useragent=self.opts['_useragent']
        )

        # Unauthenticated users are limited to 100 requests per minute, and 1000 requests per day.
        time.sleep(0.75)

        if res['content'] is None:
            self.info("No results found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from Mnemonic: {e}")
            return None

        response_code = data.get('responseCode')

        if not response_code:
            self.debug("Error retrieving search results.")
            return None

        if response_code == 402:
            self.debug("Error retrieving search results: Resource limit exceeded")
            self.errorState = True
            return None

        if response_code != 200:
            self.debug(f"Error retrieving search results: {response_code}")
            return None

        if 'data' not in data:
            self.info(f"No results found for {qry}")
            return None

        size = data.get('size')
        count = data.get('count')

        if not count or not size:
            self.info(f"No results found for {qry}")
            return None

        self.info(f"Retrieved {size} of {count} results")

        return data['data']

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        position = 0
        max_pages = int(self.opts['max_pages'])
        per_page = int(self.opts['per_page'])
        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])
        self.cohostcount = 0
        cohosts = list()

        while position < (per_page * max_pages):
            if self.checkForStop():
                break

            if self.errorState:
                break

            data = self.query(eventData, limit=per_page, offset=position)

            if data is None:
                self.info(f"No passive DNS data found for {eventData}")
                break

            position += per_page

            for r in data:
                if "*" in r['query'] or "%" in r['query']:
                    continue

                if r['lastSeenTimestamp'] < agelimit:
                    self.debug(f"Record {r['answer']} found for {r['query']} is too old, skipping.")
                    continue

                if eventName in ['IP_ADDRESS']:
                    if r['rrtype'] == 'a':
                        if self.sf.validIP(r['query']):
                            cohosts.append(r['query'])
                    continue

                if eventName in ['INTERNET_NAME', 'DOMAIN_NAME']:
                    # Ignore PTR records
                    if r['rrtype'] == 'ptr':
                        continue

                    if r['rrtype'] == 'cname':
                        if not self.getTarget().matches(r['query'], includeParents=True):
                            continue

                        cohosts.append(r['query'])

                    if self.opts['verify']:
                        continue

                    answer = r.get('answer')

                    if r['rrtype'] == 'a':
                        if not self.sf.validIP(answer):
                            continue

                        if self.sf.isValidLocalOrLoopbackIp(answer):
                            evt = SpiderFootEvent("INTERNAL_IP_ADDRESS", answer, self.__name__, event)
                        else:
                            evt = SpiderFootEvent("IP_ADDRESS", answer, self.__name__, event)
                        self.notifyListeners(evt)

                    if r['rrtype'] == 'aaaa':
                        if not self.sf.validIP6(r['answer']):
                            continue

                        if self.sf.isValidLocalOrLoopbackIp(answer):
                            evt = SpiderFootEvent("INTERNAL_IP_ADDRESS", answer, self.__name__, event)
                        else:
                            evt = SpiderFootEvent("IPV6_ADDRESS", answer, self.__name__, event)
                        self.notifyListeners(evt)

        for co in set(cohosts):
            if self.checkForStop():
                return

            if co in self.results:
                continue

            if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
                if self.opts['verify'] and not self.sf.validateIP(co, eventData):
                    self.debug(f"Host {co} no longer resolves to {eventData}")
                    continue

            if self.opts['cohostsamedomain']:
                if self.cohostcount < self.opts['maxcohost']:
                    evt = SpiderFootEvent("CO_HOSTED_SITE", co, self.__name__, event)
                    self.notifyListeners(evt)
                    self.cohostcount += 1
                continue

            if self.getTarget().matches(co, includeParents=True):
                if self.opts['verify'] and not self.sf.resolveHost(co) and not self.sf.resolveHost6(co):
                    self.debug(f"Host {co} could not be resolved")
                    evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", co, self.__name__, event)
                    self.notifyListeners(evt)
                    continue

                evt = SpiderFootEvent("INTERNET_NAME", co, self.__name__, event)
                self.notifyListeners(evt)

                if self.sf.isDomain(co, self.opts['_internettlds']):
                    evt = SpiderFootEvent("DOMAIN_NAME", co, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_mnemonic class
