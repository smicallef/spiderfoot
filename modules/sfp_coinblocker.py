# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_coinblocker
# Purpose:      Checks if a hostname is listed on CoinBlockerLists.
#
# Author:       steve@binarypool.com
#
# Created:     07/09/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_coinblocker(SpiderFootPlugin):

    meta = {
        'name': "CoinBlocker Lists",
        'summary': "Check if a domain appears on CoinBlocker lists.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://zerodot1.gitlab.io/CoinBlockerListsWeb/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://zerodot1.gitlab.io/CoinBlockerListsWeb/downloads.html",
                "https://zerodot1.gitlab.io/CoinBlockerListsWeb/references.html",
                "https://zerodot1.gitlab.io/CoinBlockerListsWeb/aboutthisproject.html"
            ],
            'favIcon': "https://zerodot1.gitlab.io/CoinBlockerListsWeb/assets/img/favicon.png",
            'logo': "https://zerodot1.gitlab.io/CoinBlockerListsWeb/assets/img/favicon.png",
            'description': "The CoinBlockerLists are a project to prevent illegal mining in "
            "browsers or other applications using IPlists and URLLists.\n"
            "It's not just to block everything without any reason, but to protect "
            "Internet users from illegal mining.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18,
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
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
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]

    def queryBlocklist(self, target):
        blocklist = self.retrieveBlocklist()

        if not blocklist:
            return False

        if target.lower() in blocklist:
            self.debug(f"Host name {target} found in CoinBlocker list.")
            return True

        return False

    def retrieveBlocklist(self):
        blocklist = self.sf.cacheGet('coinblocker', self.opts.get('cacheperiod', 24))

        if blocklist is not None:
            return self.parseBlocklist(blocklist)

        url = "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from {url}")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error(f"Received no content from {url}")
            self.errorState = True
            return None

        self.sf.cachePut("coinblocker", res['content'])

        return self.parseBlocklist(res['content'])

    def parseBlocklist(self, blocklist):
        """Parse plaintext CoinBlocker list

        Args:
            blocklist (str): plaintext CoinBlocker list

        Returns:
            list: list of blocked host names
        """
        hosts = list()

        if not blocklist:
            return hosts

        for line in blocklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue
            host = line.strip()
            # Note: Validation with sf.validHost() is too slow to use here
            # if not self.sf.validHost(host, self.opts['_internettlds']):
            #    continue
            if not host:
                continue
            hosts.append(host.lower())

        return hosts

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == "INTERNET_NAME":
            malicious_type = "MALICIOUS_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName == "AFFILIATE_INTERNET_NAME":
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == "CO_HOSTED_SITE":
            if not self.opts.get('checkcohosts', False):
                return
            malicious_type = "MALICIOUS_COHOST"
            blacklist_type = "BACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with CoinBlocker list")

        if not self.queryBlocklist(eventData):
            return

        url = "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt"
        text = f"CoinBlocker [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_coinblocker class
