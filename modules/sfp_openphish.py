# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_openphish
# Purpose:      Check if a host/domain is malicious according to OpenPhish.com.
#
# Author:       steve@binarypool.com
#
# Created:     28/06/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_openphish(SpiderFootPlugin):

    meta = {
        'name': "OpenPhish",
        'summary': "Check if a host/domain is malicious according to OpenPhish.com.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://openphish.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://openphish.com/faq.html",
                "https://openphish.com/feed.txt"
            ],
            'favIcon': "",
            'logo': "https://openphish.com/static/openphish_logo2.png",
            'description': "Timely. Accurate. Relevant Threat Intelligence.\n"
            "OpenPhish is a fully automated self-contained platform for phishing intelligence. "
            "It identifies phishing sites and performs intelligence analysis ""in real time "
            "without human intervention and without using any external resources, such as blacklists.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Hours to cache list data before re-fetching."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

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

    def queryBlacklist(self, target):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if target.lower() in blacklist:
            self.debug(f"Host name {target} found in OpenPhish blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('openphish', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://www.openphish.com/feed.txt",
            timeout=10,
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from OpenPhish.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from OpenPhish")
            self.errorState = True
            return None

        self.sf.cachePut("openphish", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from OpenPhish

        Returns:
            list: list of blacklisted host names
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if not line.startswith('http'):
                continue

            # Note: URL parsing and validation with sf.validHost() is too slow to use here
            url = line.strip().lower()
            if len(url.split("/")) < 3:
                continue
            host = url.split("/")[2]
            if not host:
                continue
            if "." not in host:
                continue
            hosts.append(host)

        return hosts

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

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
            blacklist_type = "BLACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with OpenPhish")

        if not self.queryBlacklist(eventData):
            return

        url = "https://www.openphish.com/feed.txt"
        text = f"OpenPhish [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_openphish class
