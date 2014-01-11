#-------------------------------------------------------------------------------
# Name:         sfp_malcheck
# Purpose:      Checks if an ASN, IP or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

malchecks = {
    'abuse.ch Zeus Tracker (Domain)': {
        'id': 'abusezeusdomain',
        'type': 'list',
        'checks': ['domain'],
        'url':  'https://zeustracker.abuse.ch/blocklist.php?download=baddomains'
    },
    'abuse.ch Zeus Tracker (IP)': {
        'id': 'abusezeusip',
        'type': 'list',
        'checks': ['ip'],
        'url': 'https://zeustracker.abuse.ch/blocklist.php?download=badips'
    },
    'abuse.ch SpyEye Tracker (Domain)': {
        'id': 'abusespydomain',
        'type': 'list',
        'checks': ['domain'],
        'url':  'https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist'
    },
    'abuse.ch SpyEye Tracker (IP)': {
        'id': 'abusespyip',
        'type': 'list',
        'checks': ['ip'],
        'url':  'https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist'
    },
    'abuse.ch Palevo Tracker (Domain)': {
        'id': 'abusepalevodomain',
        'type': 'list',
        'checks': ['domain'],
        'url':  'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist'
    },
    'abuse.ch Palevo Tracker (IP)': {
        'id': 'abusepalevoip',
        'type': 'list',
        'checks': ['ip'],
        'url':  'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist'
    },
    'Google SafeBrowsing (Domain/IP)': {
        'id': 'googledomain',
        'type': 'query',
        'checks': ['domain', 'ip' ],
        'url': 'http://www.google.com/safebrowsing/diagnostic?site={0}',
        'badregex': [ '.*may harm your computer.*',
            '.*this site has hosted malicious software.*'
        ],
        'goodregex': []
    },
    'Google SafeBrowsing (ASN)': {
        'id': 'googleasn',
        'type': 'query',
        'checks': ['asn'],
        'url': 'http://www.google.com/safebrowsing/diagnostic?site=AS:{0}',
        'badregex': [ '.*for example.*, that appeared to function as intermediaries.*',
            '.*this network has hosted sites that have distributed malicious.*'
        ],
        'goodregex': []
    },
    'McAfee Site Advisor': {
        'id': 'mcafeedomain',
        'type': 'query',
        'checks': ['domain'],
        'url': 'http://www.siteadvisor.com/sites/{0}',
        'badregex': ['.*This link might be dangerous.*'],
        'goodregex': []
    },
    'AVG Safety Report': {
        'id': 'avgdomain',
        'type': 'query',
        'checks': ['domain'],
        'url': 'http://www.avgthreatlabs.com/website-safety-reports/domain/{0}',
        'badregex': ['.*potentially active malware was detected.*'],
        'goodregex': []
    },
    'malwaredomains.com List': {
        'id': 'malwaredomains',
        'type': 'list',
        'checks': ['domain'],
        'url': 'https://easylist-downloads.adblockplus.org/malwaredomains_full.txt',
        'regex': '^\|\|{0}\^$'
    },
    'PhishTank': {
        'id': 'phishtank',
        'type': 'list',
        'checks': ['domain'],
        'url': 'http://data.phishtank.com/data/online-valid.csv',
        'regex': '.*,.*://{0}/.*'
    },
    'malc0de.com List': {
        'id': 'malc0de',
        'type': 'list',
        'checks': ['ip'],
        'url': 'http://malc0de.com/bl/IP_Blacklist.txt'
    },
    'TOR Node List': {
        'id': 'tornodes',
        'type': 'list',
        'checks': [ 'ip' ],
        'url': 'http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv'
    },
    'blocklist.de List': {
        'id': 'blocklistde',
        'type': 'list',
        'checks': [ 'ip' ],
        'url': 'http://lists.blocklist.de/lists/all.txt'
    }
}

class sfp_malcheck(SpiderFootPlugin):
    """Malicious Check:Check if a website, IP or ASN is considered malicious by various sources."""

    # Default options
    opts = { 
        'abusezeusdomain': True,
        'abusezeusip': True,
        'abusespydomain': True,
        'abusespyip': True,
        'abusepalevodomain': True,
        'abusepalevoip': True,
        'googledomain': True,
        'googleasn': True,
        'malwaredomains': True,
        'mcafeedomain': True,
        'avgdomain': True,
        'phishtank': True,
        'malc0de': True,
        'blocklistde': True,
        'tornodes': True,
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 48,
        'checknetblocks': True
    }

    # Option descriptions
    optdescs = {
        'abusezeusdomain': "Enable abuse.ch Zeus domain check?",
        'abusezeusip': "Enable abuse.ch Zeus IP check?",
        'abusespydomain': "Enable abuse.ch SpyEye domain check?",
        'abusespyip': "Enable abuse.ch SpeEye IP check?",
        'abusepalevodomain': "Enable abuse.ch Palevo domain check?",
        'abusepalevoip': "Enable abuse.ch Palevo IP check?",
        'googledomain': "Enable Google Safe Browsing domain check?",
        'googleasn': "Enable Google Safe Browsing ASN check?",
        'malwaredomains': "Enable malwaredomainlist.com check?",
        'mcafeedomain': "Enable McAfee Site Advisor check?",
        'avgdomain': "Enable AVG Safety check?",
        'phishtank': "Enable PhishTank check?",
        'malc0de': "Enable malc0de.com check?",
        'blocklistde': 'Enable blocklist.de check?',
        'tornodes': 'Check for potential TOR nodes?',
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod':  "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within identified netblocks?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    # Target
    baseDomain = None # calculated from the URL in setup
    results = list()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = list()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["IP_ADDRESS", "BGP_AS", "SUBDOMAIN", 
            "AFFILIATE_DOMAIN", "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "MALICIOUS_ASN", "MALICIOUS_IPADDR", "MALICIOUS_SUBDOMAIN",
            "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE" ]

    # Check the regexps to see whether the content indicates maliciousness
    def contentMalicious(self, content, goodregex, badregex):
        # First, check for the bad indicators
        if len(badregex) > 0:
            for rx in badregex:
                if re.match(rx, content, re.IGNORECASE|re.DOTALL):
                    sf.debug("Found to be bad")
                    return True

        # Finally, check for good indicators
        if len(goodregex) > 0:
            for rx in goodregex:
                if re.match(rx, content, re.IGNORECASE|re.DOTALL):
                    sf.debug("Found to be good")
                    return False

        # If nothing was matched, reply None
        sf.debug("Neither good nor bad, unknown.")
        return None

    # Look up 'query' type sources
    def resourceQuery(self, id, target):
        sf.debug("Querying " + id + " for maliciousness of " + target)
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "query":
                url = malchecks[check]['url']
                res = sf.fetchUrl(url.format(target), useragent=self.opts['_useragent'])
                if res['content'] == None:
                    return None
                if self.contentMalicious(res['content'], 
                    malchecks[check]['goodregex'],
                    malchecks[check]['badregex']):
                    return url.format(target)

        return None

    # Look up 'list' type resources
    def resourceList(self, id, target):
        sf.debug("Checking " + id + " for maliciousness of " + target)
        targetDom = sf.hostDomain(target, self.opts['_internettlds'])

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "list":
                data = dict()
                url = malchecks[check]['url']
                data['content'] = sf.cacheGet("sfmal_" + cid, self.opts['cacheperiod'])
                if data['content'] == None:
                    data = sf.fetchUrl(url, useragent=self.opts['_useragent'])
                    if data['content'] == None:
                        return None
                    else:
                        sf.cachePut("sfmal_" + cid, data['content'])

                if not malchecks[check].has_key('regex'):
                    for line in data['content'].split('\n'):
                        if line == target or line == targetDom:
                            sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
                else:
                    rxDom = malchecks[check]['regex'].format(targetDom)
                    rxTgt = malchecks[check]['regex'].format(target)
                    for line in data['content'].split('\n'):
                        if re.match(rxDom, line, re.IGNORECASE) or \
                            re.match(rxTgt, line, re.IGNORECASE):
                            sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url

        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                sf.debug("Checking maliciousness of " + target + " with: " + cid)
                if malchecks[check]['type'] == "query":
                    return self.resourceQuery(cid, target)
                if malchecks[check]['type'] == "list":
                    return self.resourceList(cid, target)

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            sf.debug("Skipping " + eventData + ", already checked.")
            return None
        else:
            self.results.append(eventData)

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return None
        if eventName == 'AFFILIATE_DOMAIN' or eventName == 'AFFILIATE_IPADDR' \
            and not self.opts['checkaffiliates']:
            return None

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            # If the module is enabled..
            if self.opts[cid]:
                if eventName in [ 'IP_ADDRESS', 'AFFILIATE_IPADDR' ]:
                    typeId = 'ip'
                    if eventName == 'IP_ADDRESS':
                        evtType = 'MALICIOUS_IPADDR'
                    else:
                        evtType = 'MALICIOUS_AFFILIATE_IPADDR'

                if eventName in [ 'BGP_AS' ]:
                    typeId = 'asn' 
                    evtType = 'MALICIOUS_ASN'

                if eventName in [ 'CO_HOSTED_SITE', 'AFFILIATE_DOMAIN', 'SUBDOMAIN' ]:
                    typeId = 'domain'
                    if eventName == 'SUBDOMAIN':
                        evtType = 'MALICIOUS_SUBDOMAIN'
                    if eventName == 'AFFILIATE_DOMAIN':
                        evtType = 'MALICIOUS_AFFILIATE'
                    if eventName == 'CO_HOSTED_SITE':
                        evtType = 'MALICIOUS_COHOST'

                url = self.lookupItem(cid, typeId, eventData)
                if self.checkForStop():
                    return None

                # Notify other modules of what you've found
                if url != None:
                    text = check + " [" + eventData + "]\n" + url
                    evt = SpiderFootEvent(evtType, text, self.__name__, event)
                    self.notifyListeners(evt)

        return None

    def start(self):
        keyword = sf.domainKeyword(self.baseDomain, self.opts['_internettlds'])
        sf.debug("Keyword extracted from " + self.baseDomain + ": " + keyword)
        if self.baseDomain in self.results:
            return None

        for check in malchecks.keys():
            if self.checkForStop():
                return None

            cid = malchecks[check]['id']
            if self.opts[cid]:
                url = self.lookupItem(cid, 'domain', self.baseDomain)
                if url != None:
                    text = check + " [" + self.baseDomain + "]\n" + url
                    evt = SpiderFootEvent('MALICIOUS_SUBDOMAIN', text, self.__name__)
                    self.notifyListeners(evt)

# End of sfp_malcheck class
