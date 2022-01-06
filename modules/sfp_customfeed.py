# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_customfeed
# Purpose:      Checks if an ASN, IP, hostname or domain is listed as malicious
#               in a user-supplied data feed.
#
# Author:       steve@binarypool.com
#
# Created:     11/11/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

malchecks = {
    'Custom Threat Data': {
        'id': '_customfeed',
        'checks': ['ip', 'netblock', 'asn', 'domain'],
        'regex': '^{0}$'
    }
}


class sfp_customfeed(SpiderFootPlugin):

    meta = {
        'name': "Custom Threat Feed",
        'summary': "Check if a host/domain, netblock, ASN or IP is malicious according to your custom feed.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"]
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'url': "",
        'cacheperiod': 0
    }

    # Option descriptions
    optdescs = {
        'url': "The URL where the feed can be found. Exact matching is performed so the format must be a single line per host, ASN, domain, IP or netblock.",
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Maximum age of data in hours before re-downloading. 0 to always download."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "AFFILIATE_INTERNET_NAME",
                "AFFILIATE_IPADDR", "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_COHOST"]

    # Look up 'list' type resources
    def resourceList(self, replaceme_id, target, targetType):
        targetDom = ''
        # Get the base domain if we're supplied a domain
        if targetType == "domain":
            targetDom = self.sf.hostDomain(target, self.opts['_internettlds'])
            if not targetDom:
                return None

        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            url = self.opts['url']
            if replaceme_id == cid:
                data = dict()
                data['content'] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))
                if data['content'] is None:
                    data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
                    if data['content'] is None:
                        self.error("Unable to fetch " + url)
                        return None
                    self.sf.cachePut("sfmal_" + cid, data['content'])

                # If we're looking at netblocks
                if targetType == "netblock":
                    iplist = list()
                    # Get the regex, replace {0} with an IP address matcher to
                    # build a list of IP.
                    # Cycle through each IP and check if it's in the netblock.
                    if 'regex' in malchecks[check]:
                        rx = malchecks[check]['regex'].replace("{0}", r"(\d+\.\d+\.\d+\.\d+)")
                        pat = re.compile(rx, re.IGNORECASE)
                        self.debug("New regex for " + check + ": " + rx)
                        for line in data['content'].split('\n'):
                            grp = re.findall(pat, line)
                            if len(grp) > 0:
                                # self.debug("Adding " + grp[0] + " to list.")
                                iplist.append(grp[0])
                    else:
                        iplist = data['content'].split('\n')

                    for ip in iplist:
                        if len(ip) < 8 or ip.startswith("#"):
                            continue
                        ip = ip.strip()

                        try:
                            if IPAddress(ip) in IPNetwork(target):
                                self.debug(f"{ip} found within netblock/subnet {target} in {check}")
                                return url
                        except Exception as e:
                            self.debug(f"Error encountered parsing: {e}")
                            continue

                    return None

                # If we're looking at hostnames/domains/IPs
                if 'regex' not in malchecks[check]:
                    for line in data['content'].split('\n'):
                        if line == target or (targetType == "domain" and line == targetDom):
                            self.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
                else:
                    # Check for the domain and the hostname
                    try:
                        rxDom = str(malchecks[check]['regex']).format(targetDom)
                        rxTgt = str(malchecks[check]['regex']).format(target)
                        for line in data['content'].split('\n'):
                            if (targetType == "domain" and re.match(rxDom, line, re.IGNORECASE)) or \
                                    re.match(rxTgt, line, re.IGNORECASE):
                                self.debug(target + "/" + targetDom + " found in " + check + " list.")
                                return url
                    except Exception as e:
                        self.debug("Error encountered parsing 2: " + str(e))
                        continue

        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.debug("Checking maliciousness of " + target + " ("
                           + itemType + ") with: " + cid)
                return self.resourceList(cid, target, itemType)

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['url'] == "":
            self.error("You enabled sfp_customfeed but defined no custom feed URL!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts.get('checkcohosts', False):
            return
        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return
        if eventName == 'NETBLOCK_OWNER' and not self.opts.get('checknetblocks', False):
            return
        if eventName == 'NETBLOCK_MEMBER' and not self.opts.get('checksubnets', False):
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
                return

            # Notify other modules of what you've found
            if url is not None:
                text = f"{check} [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_customfeed class
