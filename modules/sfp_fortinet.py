# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fortinet
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
    'Fortiguard Threat Lookup': {
        'id': '_fortiguard',
        'checks': ['ip'],
        'url': 'https://fortiguard.com/search?q={0}&engine=8',
        'badregex': ['.*Your signature is blacklisted.*'],
        'goodregex': ['.*Your signature is not blacklisted.*']
    }
}


class sfp_fortinet(SpiderFootPlugin):

    meta = {
        'name': "Fortiguard.com",
        'summary': "Check if an IP is malicious according to Fortiguard.com.",
        'flags': [""],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://fortiguard.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.fortinet.com/document/fortimail/6.0.4/rest-api-reference",
                "https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/d8d8ade1-2fd8-11e9-94bf-00505692583a/FortiMail_REST_API_Reference.pdf"
            ],
            'favIcon': "https://fortiguard.com/favicon.ico",
            'logo': "https://fortiguard.com/static/images/Fortinet-logo%20white.png?v=880",
            'description': " Fortinet empowers its customers with intelligent, seamless protection across the "
            "expanding attack surface and the power to take on ever-increasing performance requirements of "
            "the borderless network—today and into the future. "
            "Only the Fortinet Security Fabric architecture can deliver security without compromise "
            "to address the most critical security challenges, whether in networked, application, cloud, or mobile environments.",
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
                res = self.sf.fetchUrl(url.format(target), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

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

# End of sfp_fortinet class
