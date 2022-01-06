# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_cybercrimetracker
# Purpose:     Check if a host/domain or IP address is malicious according to cybercrime-tracker.net.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_cybercrimetracker(SpiderFootPlugin):

    meta = {
        'name': "CyberCrime-Tracker.net",
        'summary': "Check if a host/domain or IP address is malicious according to CyberCrime-Tracker.net.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cybercrime-tracker.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cybercrime-tracker.net/tools.php",
                "https://cybercrime-tracker.net/about.php"
            ],
            'favIcon': "https://cybercrime-tracker.net/favicon.ico",
            'logo': "https://cybercrime-tracker.net/favicon.ico",
            'description': "CyberCrime is a C&C panel tracker, in other words, "
            "it lists the administration interfaces of certain in-the-wild botnets.",
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18
    }

    # Option descriptions
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
            "IP_ADDRESS",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE"
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST"
        ]

    def queryBlacklist(self, target):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if target.lower() in blacklist:
            self.debug(f"Host name {target} found in CyberCrime-Tracker.net blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('cybercrime-tracker', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://cybercrime-tracker.net/all.php",
            timeout=10,
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from CyberCrime-Tracker.net.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from CyberCrime-Tracker.net")
            self.errorState = True
            return None

        self.sf.cachePut("cybercrime-tracker", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from CyberCrime-Tracker.net

        Returns:
            list: list of blacklisted IP addresses and host names
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue

            # Note: URL parsing and validation with sf.validHost() is too slow to use here
            host = line.split("/")[0]
            if not host:
                continue
            if "." not in host:
                continue
            hosts.append(host.split(':')[0])

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

        if eventName == 'IP_ADDRESS':
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == "INTERNET_NAME":
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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with CyberCrime-Tracker.net")

        if not self.queryBlacklist(eventData):
            return

        url = f"https://cybercrime-tracker.net/index.php?search={eventData}"
        text = f"CyberCrime-Tracker.net Malicious Submissions [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_cybercrimetracker class
