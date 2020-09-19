# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_totalhash
# Purpose:      Checks if an ASN, IP or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

malchecks = {
    'TotalHash.com Database': {
        'id': '_totalhash',
        'checks': ['ip', 'domain'],
        'url': 'https://totalhash.cymru.com/search/?dnsrr:*{0}%20or%20ip:{0}',
        'badregex': ['.*<a href=\"/analysis.*'],
        'goodregex': []
    }
}


class sfp_totalhash(SpiderFootPlugin):

    meta = {
        'name': "TotalHash.com",
        'summary': "Check if a host/domain or IP is malicious according to TotalHash.com.",
        'flags': [""],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://totalhash.cymru.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://totalhash.cymru.com/contact-us/",
                "https://totalhash.cymru.com/glossary/",
                "https://totalhash.cymru.com/browse/"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://totalhash.cymru.com/",
            'logo': "https://totalhash.cymru.com/wp-content/uploads/2014/12/TC_logo-300x141.png",
            'description': "#totalhash provides static and dynamic analysis of Malware samples. "
            "The data available on this site is free for non commercial use. "
            "If you have samples that you would like analyzed you may upload them to our anonymous FTP server.",
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'checkcohosts': True
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS",
                "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
                "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_COHOST"]

    # Check the regexps to see whether the content indicates maliciousness
    def contentMalicious(self, content, goodregex, badregex):
        # First, check for the bad indicators
        if len(badregex) > 0:
            for rx in badregex:
                if re.match(rx, content, re.IGNORECASE | re.DOTALL):
                    self.sf.debug("Found to be bad against bad regex: " + rx)
                    return True

        # Finally, check for good indicators
        if len(goodregex) > 0:
            for rx in goodregex:
                if re.match(rx, content, re.IGNORECASE | re.DOTALL):
                    self.sf.debug("Found to be good againt good regex: " + rx)
                    return False

        # If nothing was matched, reply None
        self.sf.debug("Neither good nor bad, unknown.")
        return None

    # Look up 'query' type sources
    def resourceQuery(self, id, target, targetType):
        self.sf.debug(f"Querying {id} for maliciousness of {target}")

        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if id == cid:
                url = str(malchecks[check]['url'])
                res = self.sf.fetchUrl(url.format(target), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.sf.error("Unable to fetch " + url.format(target))
                    return None

                if self.contentMalicious(res['content'], malchecks[check]['goodregex'], malchecks[check]['badregex']):
                    return url.format(target)

        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.sf.debug(f"Checking maliciousness of {target} ({itemType}) with: {cid}")
                return self.resourceQuery(cid, target, itemType)

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts.get('checkcohosts', False):
            return
        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return

        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']

            if eventName in ['IP_ADDRESS', 'AFFILIATE_IPADDR']:
                typeId = 'ip'
                if eventName == 'IP_ADDRESS':
                    evtType = 'MALICIOUS_IPADDR'
                else:
                    evtType = 'MALICIOUS_AFFILIATE_IPADDR'

            if eventName in ['BGP_AS_OWNER', 'BGP_AS_MEMBER']:
                typeId = 'asn'
                evtType = 'MALICIOUS_ASN'

            if eventName in ['INTERNET_NAME', 'CO_HOSTED_SITE',
                             'AFFILIATE_INTERNET_NAME']:
                typeId = 'domain'
                if eventName == "INTERNET_NAME":
                    evtType = "MALICIOUS_INTERNET_NAME"
                if eventName == 'AFFILIATE_INTERNET_NAME':
                    evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
                if eventName == 'CO_HOSTED_SITE':
                    evtType = 'MALICIOUS_COHOST'

            url = self.lookupItem(cid, typeId, eventData)

            if self.checkForStop():
                return

            # Notify other modules of what you've found
            if url is not None:
                text = f"{check} [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_totalhash class
