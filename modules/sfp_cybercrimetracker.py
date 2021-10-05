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
        'name': "cybercrime-tracker.net",
        'summary': "Check if a host/domain or IP address is malicious according to cybercrime-tracker.net.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://cybercrime-tracker.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cybercrime-tracker.net/tools.php",
                "https://cybercrime-tracker.net/about.php"
            ],
            'favIcon': "http://cybercrime-tracker.net/favicon.ico",
            'logo': "http://cybercrime-tracker.net/favicon.ico",
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

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "IP_ADDRESS",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
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
            self.debug(f"Host name {target} found in cybercrime-tracker.net blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('cybercrime-tracker', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "http://cybercrime-tracker.net/all.php",
            timeout=10,
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from cybercrime-tracker.net.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from cybercrime-tracker.net")
            self.errorState = True
            return None

        self.sf.cachePut("cybercrime-tracker", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from cybercrime-tracker.net

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
            hosts.append(host)

        return hosts

    # Handle events sent to this module
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

        if eventName == "IP_ADDRESS":
            evtType = 'MALICIOUS_IPADDR'
        elif eventName == "AFFILIATE_IPADDR":
            if not self.opts.get('checkaffiliates', False):
                return
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == "INTERNET_NAME":
            evtType = "MALICIOUS_INTERNET_NAME"
        elif eventName == 'AFFILIATE_INTERNET_NAME':
            if not self.opts.get('checkaffiliates', False):
                return
            evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
        elif eventName == 'CO_HOSTED_SITE':
            if not self.opts.get('checkcohosts', False):
                return
            evtType = 'MALICIOUS_COHOST'
        else:
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with cybercrime-tracker.net")

        if self.queryBlacklist(eventData):
            url = "http://cybercrime-tracker.net/all.php"
            text = f"cybercrime-tracker.net Malicious Submissions [{eventData}]\n<SFURL>{url}</SFURL>"
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_cybercrimetracker class
