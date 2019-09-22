# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_abuseipdb
# Purpose:      Checks if an ASN, IP or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     06/09/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

malchecks = {
    'AbuseIPDB Single IP': {
        'id': 'abuseipdbip',
        'type': 'query',
        'checks': ['ip'],
        'url': 'https://www.abuseipdb.com/check/{0}/json?key={1}&days={2}'
    },
    'AbuseIPDB Netblock': {
        'id': 'abuseipdbnetblock',
        'type': 'query',
        'checks': ['netblock'],
        'url': 'https://www.abuseipdb.com/check-block/json?network={0}&key={1}&days={2}'
    }
}

class sfp_abuseipdb(SpiderFootPlugin):
    """AbuseIPDB:Investigate,Passive:Reputation Systems:apikey:Check if a netblock or IP is malicious according to AbuseIPDB.com."""

    # Default options
    opts = {
        'api_key': '',
        'daysback': 30,
        'checkaffiliates': True,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'api_key': "AbuseIPDB.com API key.",
        'daysback': "How far back to query, in days?",
        'checkaffiliates': "Apply checks to affiliates?",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_OWNER", "NETBLOCK_MEMBER"] 

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR",
                "MALICIOUS_SUBNET", "MALICIOUS_NETBLOCK"]

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
        apikey = self.opts['api_key']
        daysback = self.opts['daysback']
        self.sf.debug("Querying " + id + " for maliciousness of " + target)
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "query":
                url = unicode(malchecks[check]['url'])
                res = self.sf.fetchUrl(url.format(target, apikey, daysback),
                                       timeout=self.opts['_fetchtimeout'], 
                                       useragent=self.opts['_useragent'])
                if res['content'] is None:
                    self.sf.error("Unable to fetch " + url.format(target, "masked", daysback), False)
                    return None

                try:
                    if "rate limit" in res['content']:
                        return None
                    j = json.loads(res['content'])
                    if len(j) == 0:
                        return None
                except BaseException as e:
                    self.sf.error("Malformatted JSON response: " + str(e), False)
                    return None

                return "https://www.abuseipdb.com/check/" + target

        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.sf.debug("Checking maliciousness of " + target + " (" +
                              itemType + ") with: " + cid)
                if malchecks[check]['type'] == "query":
                    return self.resourceQuery(cid, target, itemType)
        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None
        else:
            self.results[eventData] = True

        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return None
        if eventName == 'NETBLOCK_OWNER' and not self.opts.get('checknetblocks', False):
            return None
        if eventName == 'NETBLOCK_MEMBER' and not self.opts.get('checksubnets', False):
            return None

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if eventName in ['IP_ADDRESS', 'AFFILIATE_IPADDR']:
                typeId = 'ip'
                if eventName == 'IP_ADDRESS':
                    evtType = 'MALICIOUS_IPADDR'
                else:
                    evtType = 'MALICIOUS_AFFILIATE_IPADDR'

            if eventName == 'NETBLOCK_OWNER':
                typeId = 'netblock'
                evtType = 'MALICIOUS_NETBLOCK'
            if eventName == 'NETBLOCK_MEMBER':
                typeId = 'netblock'
                evtType = 'MALICIOUS_SUBNET'

            url = self.lookupItem(cid, typeId, eventData)
            if self.checkForStop():
                return None

            # Notify other modules of what you've found
            if url is not None:
                text = check + " [" + eventData + "]\n" + "<SFURL>" + url + "</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_abuseipdb class
