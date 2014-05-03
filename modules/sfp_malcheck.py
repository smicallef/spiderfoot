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

from netaddr import IPAddress, IPNetwork
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
        'checks': ['ip', 'netblock'],
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
        'checks': ['ip', 'netblock'],
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
        'checks': ['ip', 'netblock'],
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
    'malwaredomains.com IP List': {
        'id': 'malwaredomainsip',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://www.malwaredomainlist.com/hostslist/ip.txt'
    },
    'malwaredomains.com Domain List': {
        'id': 'malwaredomainsdomain',
        'type': 'list',
        'checks': ['domain'],
        'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
        'regex': '.*\s+{0}[\s$]'
    },
    'PhishTank': {
        'id': 'phishtank',
        'type': 'list',
        'checks': ['domain'],
        'url': 'http://data.phishtank.com/data/online-valid.csv',
        'regex': '\d+,\w+://(.*\.)?[^a-zA-Z0-9]?{0}.*,http://www.phishtank.com/.*'
    },
    'malc0de.com List': {
        'id': 'malc0de',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://malc0de.com/bl/IP_Blacklist.txt'
    },
    'TOR Node List': {
        'id': 'tornodes',
        'type': 'list',
        'checks': [ 'ip', 'netblock' ],
        'url': 'http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv'
    },
    'blocklist.de List': {
        'id': 'blocklistde',
        'type': 'list',
        'checks': [ 'ip', 'netblock' ],
        'url': 'http://lists.blocklist.de/lists/all.txt'
    },
    'Autoshun.org List': {
        'id': 'autoshun',
        'type': 'list',
        'checks': [ 'ip', 'netblock' ],
        'url': 'http://www.autoshun.org/files/shunlist.csv',
        'regex': '{0},.*'
    },
    'Internet Storm Center': {
        'id': 'isc',
        'type': 'query',
        'checks': [ 'ip' ],
        'url': 'https://isc.sans.edu/api/ip/{0}',
        'badregex': [ '.*attacks.*' ],
        'goodregex': []
    },
    'AlienVault IP Reputation Database': {
        'id': 'alienvault',
        'type': 'list',
        'checks': [ 'ip', 'netblock' ],
        'url': 'https://reputation.alienvault.com/reputation.generic',
        'regex': '{0} #.*'
    },
    'OpenBL.org Blacklist': {
        'id': 'openbl',
        'type': 'list',
        'checks': [ 'ip', 'netblock' ],
        'url': 'http://www.openbl.org/lists/base.txt'
    },
    'ThreatExpert.com Database': {
        'id': 'threatexpert',
        'type': 'query',
        'checks': [ 'ip', 'domain' ],
        'url': 'http://www.threatexpert.com/reports.aspx?find={0}&tf=3',
        'badregex': [ '.*<strong>Findings</strong>.*' ],
        'goodregex': []
    },
    'TotalHash.com Database': {
        'id': 'totalhash',
        'type': 'query',
        'checks': [ 'ip', 'domain' ],
        'url': 'http://totalhash.com/search/dnsrr:*{0}%20or%20ip:{0}',
        'badregex': [ '.*<a href=\"/analysis.*' ],
        'goodregex': []
    },
    'Nothink.org SSH Scanners': {
        'id': 'nothinkssh',
        'type': 'list',
        'checks': [ 'ip', 'netblock', 'domain' ],
        'url': 'http://www.nothink.org/blacklist/blacklist_ssh_week.txt'
    },
    'Nothink.org Malware IRC Traffic': {
        'id': 'nothinkirc',
        'type': 'list',
        'checks': [ 'ip', 'netblock', 'domain' ],
        'url': 'http://www.nothink.org/blacklist/blacklist_malware_irc.txt'
    },
    'Nothink.org Malware HTTP Traffic': {
        'id': 'nothinkhttp',
        'type': 'list',
        'checks': [ 'ip', 'netblock', 'domain' ],
        'url': 'http://www.nothink.org/blacklist/blacklist_malware_http.txt'
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
        'malwaredomainsdomain': True,
        'malwaredomainsip': True,
        'mcafeedomain': True,
        'avgdomain': True,
        'phishtank': True,
        'malc0de': True,
        'blocklistde': True,
        'autoshun': True,
        'isc': True,
        'tornodes': True,
        'alienvault': True,
        'openbl': True,
        'totalhash': True,
        'threatexpert': True,
        'nothinkssh': True,
        'nothinkirc': True,
        'nothinkhttp': True,
        'aaacheckaffiliates': True, # prefix with aaa so they appear on the top of the UI list
        'aaacheckcohosts': True,
        'aaacacheperiod': 18,
        'aaachecknetblocks': True,
        'aaachecksubnets': True
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
        'malwaredomainsdomain': "Enable malwaredomainlist.com domain check?",
        'malwaredomainsip': "Enable malwaredomainlist.com IP check?",
        'mcafeedomain': "Enable McAfee Site Advisor check?",
        'avgdomain': "Enable AVG Safety check?",
        'phishtank': "Enable PhishTank check?",
        'malc0de': "Enable malc0de.com check?",
        'blocklistde': 'Enable blocklist.de check?',
        'tornodes': 'Enable TOR exit node check?',
        'autoshun': 'Enable Autoshun.org check?',
        'isc': 'Enable Internet Storm Center check?',
        'alienvault': 'Enable AlienVault IP Reputation check?',
        'openbl': 'Enable OpenBL.org Blacklist check?',
        'totalhash': 'Enable totalhash.com check?',
        'threatexpert': 'Enable threatexpert.com check?',
        'nothinkssh': 'Enable Nothink.org SSH attackers check?',
        'nothinkirc': 'Enable Nothink.org Malware DNS traffic check?',
        'nothinkhttp': 'Enable Nothink.org Malware HTTP traffic check?',
        'aaacheckaffiliates': "Apply checks to affiliates?",
        'aaacheckcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'aaacacheperiod':  "Hours to cache list data before re-fetching.",
        'aaachecknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'aaachecksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = list()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = list()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["DOMAIN_NAME", "IP_ADDRESS", "BGP_AS", "SUBDOMAIN", 
            "IP_SUBNET", "AFFILIATE_DOMAIN", "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE", "NETBLOCK" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "MALICIOUS_ASN", "MALICIOUS_IPADDR", "MALICIOUS_SUBDOMAIN",
            "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE", "MALICIOUS_SUBNET",
            "MALICIOUS_COHOST", "MALICIOUS_DOMAIN_NAME" ]

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
    def resourceQuery(self, id, target, targetType):
        sf.debug("Querying " + id + " for maliciousness of " + target)
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "query":
                url = unicode(malchecks[check]['url'])
                res = sf.fetchUrl(url.format(target), useragent=self.opts['_useragent'])
                if res['content'] == None:
                    sf.error("Unable to fetch " + url.format(target), False)
                    return None
                if self.contentMalicious(res['content'], 
                    malchecks[check]['goodregex'],
                    malchecks[check]['badregex']):
                    return url.format(target)

        return None

    # Look up 'list' type resources
    def resourceList(self, id, target, targetType):
        targetDom = ''
        # Get the base domain if we're supplied a domain
        if targetType == "domain":
            targetDom = sf.hostDomain(target, self.opts['_internettlds'])

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "list":
                data = dict()
                url = malchecks[check]['url']
                data['content'] = sf.cacheGet("sfmal_" + cid, self.opts['aaacacheperiod'])
                if data['content'] == None:
                    data = sf.fetchUrl(url, useragent=self.opts['_useragent'])
                    if data['content'] == None:
                        sf.error("Unable to fetch " + url, False)
                        return None
                    else:
                        sf.cachePut("sfmal_" + cid, data['content'])

                # If we're looking at netblocks
                if targetType == "netblock":
                    iplist = list()
                    # Get the regex, replace {0} with an IP address matcher to 
                    # build a list of IP.
                    # Cycle through each IP and check if it's in the netblock.
                    if malchecks[check].has_key('regex'):
                        rx = rxTgt = malchecks[check]['regex'].replace("{0}", \
                            "(\d+\.\d+\.\d+\.\d+)")
                        sf.debug("New regex for " + check + ": " + rx)
                        for line in data['content'].split('\n'):
                            grp = re.findall(rx, line, re.IGNORECASE)
                            if len(grp) > 0:
                                #sf.debug("Adding " + grp[0] + " to list.")
                                iplist.append(grp[0])
                    else:
                        iplist = data['content'].split('\n')

                    for ip in iplist:
                        if len(ip) < 8 or ip.startswith("#"):
                            continue
                        ip = ip.strip()

                        try:
                            if IPAddress(ip) in IPNetwork(target):
                                sf.debug(ip + " found within netblock/subnet " + \
                                    target + " in " + check)
                                return url
                        except Exception as e:
                                sf.debug("Error encountered parsing: " + str(e))
                                continue

                    return None

                # If we're looking at hostnames/domains/IPs
                if not malchecks[check].has_key('regex'):
                    for line in data['content'].split('\n'):
                        if line == target or (targetType == "domain" and line == targetDom):
                            sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
                else:
                    # Check for the domain and the hostname
                    rxDom = unicode(malchecks[check]['regex']).format(targetDom)
                    rxTgt = unicode(malchecks[check]['regex']).format(target)
                    for line in data['content'].split('\n'):
                        if (targetType == "domain" and re.match(rxDom, line, re.IGNORECASE)) or \
                            re.match(rxTgt, line, re.IGNORECASE):
                            sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                sf.debug("Checking maliciousness of " + target + " (" +  \
                    itemType + ") with: " + cid)
                if malchecks[check]['type'] == "query":
                    return self.resourceQuery(cid, target, itemType)
                if malchecks[check]['type'] == "list":
                    return self.resourceList(cid, target, itemType)

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

        if eventName == 'CO_HOSTED_SITE' and not self.opts['aaacheckcohosts']:
            return None
        if eventName == 'AFFILIATE_DOMAIN' or eventName == 'AFFILIATE_IPADDR' \
            and not self.opts['aaacheckaffiliates']:
            return None
        if eventName == 'NETBLOCK' and not self.opts['aaachecknetblocks']:
            return None
        if eventName == 'IP_SUBNET' and not self.opts['aaachecksubnets']:
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

                if eventName in [ 'DOMAIN_NAME', 'CO_HOSTED_SITE', 
                    'AFFILIATE_DOMAIN', 'SUBDOMAIN' ]:
                    typeId = 'domain'
                    if eventName  == 'SUBDOMAIN':
                        evtType = 'MALICIOUS_SUBDOMAIN'
                    if eventName == "DOMAIN_NAME":
                        evtType = "MALICIOUS_DOMAIN_NAME"
                    if eventName == 'AFFILIATE_DOMAIN':
                        evtType = 'MALICIOUS_AFFILIATE'
                    if eventName == 'CO_HOSTED_SITE':
                        evtType = 'MALICIOUS_COHOST'

                if eventName == 'NETBLOCK':
                    typeId = 'netblock'
                    evtType = 'MALICIOUS_NETBLOCK'
                if eventName == 'IP_SUBNET':
                    typeId = 'netblock'
                    evtType = 'MALICIOUS_SUBNET'

                url = self.lookupItem(cid, typeId, eventData)
                if self.checkForStop():
                    return None

                # Notify other modules of what you've found
                if url != None:
                    text = check + " [" + eventData + "]\n" + "<SFURL>" + url + "</SFURL>"
                    evt = SpiderFootEvent(evtType, text, self.__name__, event)
                    self.notifyListeners(evt)

        return None

# End of sfp_malcheck class
