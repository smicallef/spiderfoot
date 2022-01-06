# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_phishtank
# Purpose:      Check if a host/domain is malicious according to PhishTank.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_phishtank(SpiderFootPlugin):

    meta = {
        'name': "PhishTank",
        'summary': "Check if a host/domain is malicious according to PhishTank.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://phishtank.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://phishtank.com/developer_info.php"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://phishtank.com/",
            'logo': "https://phishtank.com/images/logo_with_tagline.gif",
            'description': "Submit suspected phishes. Track the status of your submissions. Verify other users' submissions.",
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

        for item in blacklist:
            if not item:
                continue
            if target.lower() in item[1]:
                self.debug(f"Host name {target} found in phishtank.com blacklist.")
                return item[0]

        return None

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('phishtank', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://data.phishtank.com/data/online-valid.csv",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from phishtank.com.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from phishtank.com")
            self.errorState = True
            return None

        self.sf.cachePut("phishtank", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from phishtank.com

        Returns:
            list: list of blacklisted host names and associated PhishTank IDs
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue
            phish_id = line.strip().split(",")[0]
            url = str(line.strip().split(",")[1]).lower()
            # Note: URL parsing and validation with sf.validHost() is too slow to use here
            if len(url.split("/")) < 3:
                continue
            host = url.split("/")[2]
            if not host:
                continue
            if "." not in host:
                continue
            hosts.append([phish_id, host])

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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with phishtank.com")

        phish_id = self.queryBlacklist(eventData)

        if not phish_id:
            return

        url = f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}"
        text = f"PhishTank [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_phishtank class
