# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_botvrij
# Purpose:      Check if a domain is malicious according to botvrij.eu.
#
# Author:       steve@binarypool.com
#
# Created:     16/05/2020
# Copyright:   (c) Steve Micallef, 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_botvrij(SpiderFootPlugin):

    meta = {
        'name': "botvrij.eu",
        'summary': "Check if a domain is malicious according to botvrij.eu.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://botvrij.eu/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Botvrij.eu provides different sets "
                " of open source IOCs that you can use in your "
                " security devices to detect possible malicious activity.\n"
                "The information contains network info (IPs), file hashes,"
                " file paths, domain names, URLs.",
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
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST"
        ]

    def queryBlacklist(self, target):
        blacklist = self.retrieveBlacklist()

        if target.lower() in blacklist:
            self.sf.debug(f"Host name {target} found in botvrij.eu blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('botvrij', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://www.botvrij.eu/data/blocklist/blocklist_full.csv",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.sf.error(f"Unexpected HTTP response code {res['code']} from botvrij.eu.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.error("Received no content from botvrij.eu")
            self.errorState = True
            return None

        self.sf.cachePut("botvrij", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from botvrij.eu

        Returns:
            list: list of blacklisted host names
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue
            host = line.strip().split(",")[0].lower()
            # Note: Validation with sf.validHost() is too slow to use here
            # if not self.sf.validHost(host, self.opts['_internettlds']):
            #    continue
            hosts.append(host)

        return hosts

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == "INTERNET_NAME":
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

        self.sf.debug(f"Checking maliciousness of {eventData} ({eventName}) with botvrij.eu")

        if self.queryBlacklist(eventData):
            url = "https://www.botvrij.eu/data/blocklist/blocklist_full.csv"
            text = f"botvrij.eu Domain Blocklist [{eventData}]\n<SFURL>{url}</SFURL>"
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_botvrij class
