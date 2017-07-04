# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_nothink
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
    }
}

class sfp_nothink(SpiderFootPlugin):
    """Nothink.org:Investigate,Passive:Reputation Systems:slow:Check if a host/domain, netblock or IP is malicious according to Nothink.org."""


    # Default options
    opts = {
        'nothinkssh': True,
        'nothinkirc': True,
        'nothinkhttp': True,
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'nothinkssh': 'Enable Nothink.org SSH attackers check?',
        'nothinkirc': 'Enable Nothink.org Malware DNS traffic check?',
        'nothinkhttp': 'Enable Nothink.org Malware HTTP traffic check?',
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
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
        return ["INTERNET_NAME", "IP_ADDRESS",
                "NETBLOCK_MEMBER", "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
                "CO_HOSTED_SITE", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
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
                res = self.sf.fetchUrl(url.format(target), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
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
                data['content'] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))
                if data['content'] is None:
                    data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
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

        if eventName == 'CO_HOSTED_SITE' and not self.opts.get('checkcohosts', False):
            return None
        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return None
        if eventName == 'NETBLOCK_OWNER' and not self.opts.get('checknetblocks', False):
            return None
        if eventName == 'NETBLOCK_MEMBER' and not self.opts.get('checksubnets', False):
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

# End of sfp_nothink class
