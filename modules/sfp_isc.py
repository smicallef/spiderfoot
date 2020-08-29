# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_isc
# Purpose:      Checks if an ASN, IP or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from sflib import SpiderFootPlugin, SpiderFootEvent

malchecks = {
    'Internet Storm Center': {
        'id': '_isc',
        'checks': ['ip'],
        'url': 'https://isc.sans.edu/api/ip/{0}',
        'badregex': [r'.*<attacks>\d+</attacks>.*'],
        'goodregex': []
    }
}


class sfp_isc(SpiderFootPlugin):

    meta = {
        'name': "Internet Storm Center",
        'summary': "Check if an IP is malicious according to SANS ISC.",
        'flags': [""],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://isc.sans.edu",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://isc.sans.edu/api/",
                "https://isc.sans.edu/howto.html",
                "https://isc.sans.edu/honeypot.html",
                "https://isc.sans.edu/glossary.html",
                "https://isc.sans.edu/fightback.html"
            ],
            'favIcon': "https://isc.sans.edu/iscfavicon.ico",
            'logo': "https://isc.sans.edu/images/logos/isc/large.png",
            'description': "The ISC provides a free analysis and warning service to thousands of Internet users "
                                "and organizations, and is actively working with Internet Service Providers to "
                                "fight back against the most malicious attackers.\n"
                                "Thousands of sensors that work with most firewalls, intrusion detection systems, "
                                "home broadband devices, and nearly all operating systems are constantly collecting information about "
                                "unwanted traffic arriving from the Internet. "
                                "These devices feed the DShield database where human volunteers as well as machines pour through "
                                "the data looking for abnormal trends and behavior. "
                                "The resulting analysis is posted to the ISC's main web page where it can be automatically retrieved "
                                "by simple scripts or can be viewed in near real time by any Internet user.",
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?"
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR"]

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
                res = self.sf.fetchUrl(url.format(target), timeout=30, useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.sf.error("Unable to fetch " + url.format(target), False)
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
            return None

        self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts.get('checkcohosts', False):
            return None
        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return None

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
                return None

            # Notify other modules of what you've found
            if url is not None:
                text = f"{check} [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_isc class
