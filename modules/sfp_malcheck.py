# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_malcheck
# Purpose:      Checks if an ASN, IP or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

malchecks = {
    'abuse.ch Zeus Tracker (Domain)': {
        'id': 'abusezeusdomain',
        'type': 'list',
        'checks': ['domain'],
        'url': 'https://zeustracker.abuse.ch/blocklist.php?download=baddomains'
    },
    'abuse.ch Zeus Tracker (IP)': {
        'id': 'abusezeusip',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://zeustracker.abuse.ch/blocklist.php?download=badips'
    },
    'abuse.ch Feodo Tracker (Domain)': {
        'id': 'abusefeododomain',
        'type': 'list',
        'checks': ['domain'],
        'url': 'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist'
    },
    'abuse.ch Feodo Tracker (IP)': {
        'id': 'abusefeodoip',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist'
    },
    'abuse.ch Palevo Tracker (Domain)': {
        'id': 'abusepalevodomain',
        'type': 'list',
        'checks': ['domain'],
        'url': 'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist'
    },
    'abuse.ch Palevo Tracker (IP)': {
        'id': 'abusepalevoip',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist'
    },
    'abuse.ch SSL Blacklist (IP)': {
        'id': 'abusesslblip',
        'type': 'list',
        'checks': ['ip'],
        'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
        'regex': '{0},.*'
    },
    'Google SafeBrowsing (Domain/IP)': {
        'id': 'googledomain',
        'type': 'query',
        'checks': ['domain', 'ip'],
        'url': 'http://www.google.com/safebrowsing/diagnostic?site={0}',
        'badregex': ['.*not safe to visit.*'],
        'goodregex': []
    },
    'Google SafeBrowsing (ASN)': {
        'id': 'googleasn',
        'type': 'query',
        'checks': ['asn'],
        'url': 'http://www.google.com/safebrowsing/diagnostic?site=AS:{0}',
        'badregex': ['.*for example.*, that appeared to function as intermediaries.*',
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
    'malwaredomainlist.com IP List': {
        'id': 'malwaredomainlistip',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://www.malwaredomainlist.com/hostslist/ip.txt'
    },
    'malwaredomainlist.com Domain List': {
        'id': 'malwaredomainlistdomain',
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
        'checks': ['ip', 'netblock'],
        'url': 'http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv'
    },
    'blocklist.de List': {
        'id': 'blocklistde',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://lists.blocklist.de/lists/all.txt'
    },
    'Autoshun.org List': {
        'id': 'autoshun',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://www.autoshun.org/files/shunlist.csv',
        'regex': '{0},.*'
    },
    'Internet Storm Center': {
        'id': 'isc',
        'type': 'query',
        'checks': ['ip'],
        'url': 'https://isc.sans.edu/api/ip/{0}',
        'badregex': ['.*<attacks>\d+</attacks>.*'],
        'goodregex': []
    },
    'AlienVault IP Reputation Database': {
        'id': 'alienvault',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://reputation.alienvault.com/reputation.generic',
        'regex': '{0} #.*'
    },
    'OpenBL.org Blacklist': {
        'id': 'openbl',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://www.openbl.org/lists/base.txt'
    },
    'ThreatExpert.com Database': {
        'id': 'threatexpert',
        'type': 'query',
        'checks': ['ip', 'domain'],
        'url': 'http://www.threatexpert.com/reports.aspx?find={0}&tf=3',
        'badregex': ['.*<strong>Findings</strong>.*'],
        'goodregex': []
    },
    'TotalHash.com Database': {
        'id': 'totalhash',
        'type': 'query',
        'checks': ['ip', 'domain'],
        'url': 'http://totalhash.com/search/dnsrr:*{0}%20or%20ip:{0}',
        'badregex': ['.*<a href=\"/analysis.*'],
        'goodregex': []
    },
    'Nothink.org SSH Scanners': {
        'id': 'nothinkssh',
        'type': 'list',
        'checks': ['ip', 'netblock', 'domain'],
        'url': 'http://www.nothink.org/blacklist/blacklist_ssh_week.txt'
    },
    'Nothink.org Malware IRC Traffic': {
        'id': 'nothinkirc',
        'type': 'list',
        'checks': ['ip', 'netblock', 'domain'],
        'url': 'http://www.nothink.org/blacklist/blacklist_malware_irc.txt'
    },
    'Nothink.org Malware HTTP Traffic': {
        'id': 'nothinkhttp',
        'type': 'list',
        'checks': ['ip', 'netblock', 'domain'],
        'url': 'http://www.nothink.org/blacklist/blacklist_malware_http.txt'
    },
    'malwaredomains.com Domains': {
        'id': 'malwaredomains',
        'type': 'list',
        'checks': ['domain'],
        'url': 'http://mirror2.malwaredomains.com/files/domains.txt',
        'regex': '.*\t{0}\t[a-zA-Z].*'
    },
    'packetmail.net List': {
        'id': 'packetmail',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://www.packetmail.net/iprep.txt',
        'regex': '{0};.*'
    },
    'packetmail.net CARISIRT': {
        'id': 'packetmailcarisirt',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://www.packetmail.net/iprep_CARISIRT.txt',
        'regex': '{0};.*'
    },
    'packetmail.net ramnode': {
        'id': 'packetmailramnode',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'https://www.packetmail.net/iprep_ramnode.txt',
        'regex': '{0};.*'
    },
    'bitcash.cz Blacklist': {
        'id': 'bitcash',
        'type': 'list',
        'checks': [ 'ip' ],
        'url': 'http://bitcash.cz/misc/log/blacklist',
        'regex': '{0}\s+.*'
    },
    'maxmind.com Open Proxy List': {
        'id': 'maxmind',
        'type': 'list',
        'checks': [ 'ip' ],
        'url': 'https://www.maxmind.com/en/proxy-detection-sample-list',
        'regex': '.*proxy-detection-sample/{0}\".*'
    },
    'cybercrime-tracker.net Malicious Submissions': {
        'id': 'cybercrime',
        'type': 'query',
        'checks': ['ip', 'domain'],
        'url': 'http://cybercrime-tracker.net/query.php?url={0}',
        'badregex': ['.*malicious.*'],
        'goodregex': []
    },
    'hosts-file.net Malicious Hosts': {
        'id': 'hphosts',
        'type': 'list',
        'checks': ['domain'],
        'url': 'http://hosts-file.net/download/hosts.txt',
        'regex': '^127.0.0.1\s+{0}$'
    },
    'multiproxy.org Open Proxies': {
        'id': 'multiproxy',
        'type': 'list',
        'checks': ['ip'],
        'url': 'http://multiproxy.org/txt_all/proxy.txt',
        'regex': '{0}:.*'
    },
    'spys.ru Free Proxy List': {
        'id': 'spysproxy',
        'type': 'list',
        'checks': ['ip'],
        'url': 'http://txt.proxyspy.net/proxy.txt',
        'regex': '{0}:.*'
    },
    'badips.com IP Reptutation List': {
        'id': 'badips',
        'type': 'list',
        'checks': ['ip', 'domain'],
        'url': 'https://www.badips.com/get/list/any/1?age=24h',
        'regex': '{0}'
    },
    'VXVault Malicious URL List': {
        'id': 'vxvault',
        'type': 'list',
        'checks': ['ip', 'domain'],
        'url': 'http://vxvault.net/URL_List.php',
        'regex': '.*\/{0}/.*'
    },
    'VOIPBL Publicly Accessible PBX List': {
        'id': 'voipbl',
        'type': 'list',
        'checks': ['ip', 'netblock'],
        'url': 'http://www.voipbl.org/update',
        'regex': '{0}\/'
    }
}


class sfp_malcheck(SpiderFootPlugin):
    """Malicious Check:Investigate,Passive:Blacklists:slow:Check if a website, IP or ASN is considered malicious by various sources. Includes TOR exit nodes and open proxies."""

    # Default options
    opts = {
        'abusezeusdomain': True,
        'abusezeusip': True,
        'abusefeododomain': True,
        'abusefeodoip': True,
        'abusepalevodomain': True,
        'abusepalevoip': True,
        'abusesslblip': True,
        'googledomain': True,
        'googleasn': True,
        'bitcash': True,
        'maxmind': True,
        'malwaredomainlistdomain': True,
        'malwaredomainlistip': True,
        'malwaredomains': True,
        'mcafeedomain': True,
        'cybercrime': True,
        'hphosts': True,
        'avgdomain': True,
        'phishtank': True,
        'malc0de': True,
        'blocklistde': True,
        'autoshun': True,
        'isc': True,
        'badips': True,
        'tornodes': True,
        'multiproxy': True,
        'alienvault': True,
        'openbl': True,
        'spysproxy': True,
        'totalhash': True,
        'threatexpert': True,
        'nothinkssh': True,
        'nothinkirc': True,
        'nothinkhttp': True,
        'vxvault': True,
        'voipbl': True,
        'packetmail': True,
        'packetmailcarisirt': True,
        'packetmailramnode': True,
        'aaacheckaffiliates': True,  # prefix with aaa so they appear on the top of the UI list
        'aaacheckcohosts': True,
        'aaacacheperiod': 18,
        'aaachecknetblocks': True,
        'aaachecksubnets': True
    }

    # Option descriptions
    optdescs = {
        'abusezeusdomain': "Enable abuse.ch Zeus domain check?",
        'abusezeusip': "Enable abuse.ch Zeus IP check?",
        'abusefeododomain': "Enable abuse.ch Feodo domain check?",
        'abusefeodoip': "Enable abuse.ch Feodo IP check?",
        'abusepalevodomain': "Enable abuse.ch Palevo domain check?",
        'abusepalevoip': "Enable abuse.ch Palevo IP check?",
        'abusesslblip': "Enable abuse.ch SSL Backlist IP check?",
        'googledomain': "Enable Google Safe Browsing domain check?",
        'googleasn': "Enable Google Safe Browsing ASN check?",
        'bitcash': "Enable bitcash.cz Blocklist check?",
        'maxmind': "Enable maxmind.com Open Proxy list check?",
        'malwaredomainlistdomain': "Enable malwaredomainlist.com domain check?",
        'malwaredomainlistip': "Enable malwaredomainlist.com IP check?",
        'malwaredomains': "Enable malwaredomains.com Domain check?",
        'mcafeedomain': "Enable McAfee Site Advisor check?",
        'avgdomain': "Enable AVG Safety check?",
        'phishtank': "Enable PhishTank check?",
        'malc0de': "Enable malc0de.com check?",
        'blocklistde': 'Enable blocklist.de check?',
        'tornodes': 'Enable TOR exit node check?',
        'cybercrime': 'Enable cybercrime-tracker.net Malicious IP check?',
        'hphosts': 'Enable hosts-file.net Malicious Hosts check?',
        'spysproxy': 'Enable spys.ru Free Proxy lookup?',
        'badips': 'Enable badips.com IP lookup?',
        'multiproxy': 'Enable multiproxy.org Open Proxy lookup?',
        'autoshun': 'Enable Autoshun.org check?',
        'isc': 'Enable Internet Storm Center check?',
        'alienvault': 'Enable AlienVault IP Reputation check?',
        'openbl': 'Enable OpenBL.org Blacklist check?',
        'totalhash': 'Enable totalhash.com check?',
        'vxvault': 'Enable VXVault Malicious URL check (checks hostnames and IPs)?',
        'voipbl': 'Enable checking for publicly accessible PBXs in VOIPBL?',
        'threatexpert': 'Enable threatexpert.com check?',
        'nothinkssh': 'Enable Nothink.org SSH attackers check?',
        'nothinkirc': 'Enable Nothink.org Malware DNS traffic check?',
        'nothinkhttp': 'Enable Nothink.org Malware HTTP traffic check?',
        'packetmail': 'Enable packetmail.net honeypot IP reputation list?',
        'packetmailcarisirt': 'Enable packetmail.net honeypot IP reputation CARISIRT list?',
        'packetmailramnode': 'Enable packetmail.net honeypot IP reputation ramnode list?',
        'aaacheckaffiliates': "Apply checks to affiliates?",
        'aaacheckcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'aaacacheperiod': "Hours to cache list data before re-fetching.",
        'aaachecknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'aaachecksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "BGP_AS_OWNER", "BGP_AS_MEMBER",
                "NETBLOCK_MEMBER", "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
                "CO_HOSTED_SITE", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_ASN", "MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_SUBNET", "MALICIOUS_COHOST", "MALICIOUS_NETBLOCK"]

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
        self.sf.debug("Querying " + id + " for maliciousness of " + target)
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "query":
                url = unicode(malchecks[check]['url'])
                res = self.sf.fetchUrl(url.format(target), useragent=self.opts['_useragent'])
                if res['content'] is None:
                    self.sf.error("Unable to fetch " + url.format(target), False)
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
            targetDom = self.sf.hostDomain(target, self.opts['_internettlds'])

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "list":
                data = dict()
                url = malchecks[check]['url']
                data['content'] = self.sf.cacheGet("sfmal_" + cid, self.opts['aaacacheperiod'])
                if data['content'] is None:
                    data = self.sf.fetchUrl(url, useragent=self.opts['_useragent'])
                    if data['content'] is None:
                        self.sf.error("Unable to fetch " + url, False)
                        return None
                    else:
                        self.sf.cachePut("sfmal_" + cid, data['content'])

                # If we're looking at netblocks
                if targetType == "netblock":
                    iplist = list()
                    # Get the regex, replace {0} with an IP address matcher to 
                    # build a list of IP.
                    # Cycle through each IP and check if it's in the netblock.
                    if 'regex' in malchecks[check]:
                        rx = malchecks[check]['regex'].replace("{0}",
                                                               "(\d+\.\d+\.\d+\.\d+)")
                        pat = re.compile(rx, re.IGNORECASE)
                        self.sf.debug("New regex for " + check + ": " + rx)
                        for line in data['content'].split('\n'):
                            grp = re.findall(pat, line)
                            if len(grp) > 0:
                                #self.sf.debug("Adding " + grp[0] + " to list.")
                                iplist.append(grp[0])
                    else:
                        iplist = data['content'].split('\n')

                    for ip in iplist:
                        if len(ip) < 8 or ip.startswith("#"):
                            continue
                        ip = ip.strip()

                        try:
                            if IPAddress(ip) in IPNetwork(target):
                                self.sf.debug(ip + " found within netblock/subnet " +
                                              target + " in " + check)
                                return url
                        except Exception as e:
                            self.sf.debug("Error encountered parsing: " + str(e))
                            continue

                    return None

                # If we're looking at hostnames/domains/IPs
                if 'regex' not in malchecks[check]:
                    for line in data['content'].split('\n'):
                        if line == target or (targetType == "domain" and line == targetDom):
                            self.sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
                else:
                    # Check for the domain and the hostname
                    rxDom = unicode(malchecks[check]['regex']).format(targetDom)
                    rxTgt = unicode(malchecks[check]['regex']).format(target)
                    for line in data['content'].split('\n'):
                        if (targetType == "domain" and re.match(rxDom, line, re.IGNORECASE)) or \
                                re.match(rxTgt, line, re.IGNORECASE):
                            self.sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.sf.debug("Checking maliciousness of " + target + " (" +
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

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None
        else:
            self.results.append(eventData)

        if eventName == 'CO_HOSTED_SITE' and not self.opts['aaacheckcohosts']:
            return None
        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts['aaacheckaffiliates']:
            return None
        if eventName == 'NETBLOCK_OWNER' and not self.opts['aaachecknetblocks']:
            return None
        if eventName == 'NETBLOCK_MEMBER' and not self.opts['aaachecksubnets']:
            return None

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            # If the module is enabled..
            if self.opts[cid]:
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
                                 'AFFILIATE_INTERNET_NAME', ]:
                    typeId = 'domain'
                    if eventName == "INTERNET_NAME":
                        evtType = "MALICIOUS_INTERNET_NAME"
                    if eventName == 'AFFILIATE_INTERNET_NAME':
                        evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
                    if eventName == 'CO_HOSTED_SITE':
                        evtType = 'MALICIOUS_COHOST'

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

# End of sfp_malcheck class
