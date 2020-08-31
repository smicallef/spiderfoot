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

from netaddr import IPAddress, IPNetwork

from sflib import SpiderFootEvent, SpiderFootPlugin

malchecks = {
    'AbuseIPDB': {
        'id': 'abuseipdbip',
        'checks': ['ip'],
        'url': 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={0}&plaintext=1'
    }
}

class sfp_abuseipdb(SpiderFootPlugin):

    meta = {
        'name': "AbuseIPDB",
        'summary': "Check if an IP address is malicious according to AbuseIPDB.com.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.abuseipdb.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.abuseipdb.com/#introduction",
                "https://www.abuseipdb.com/fail2ban.html",
                "https://www.abuseipdb.com/csf",
                "https://www.abuseipdb.com/suricata",
                "https://www.abuseipdb.com/splunk",
                "https://www.abuseipdb.com/categories"
            ],
            'apiKeyInstructions': [
                "Visit https://www.abuseipdb.com/pricing",
                "Select the plan required",
                "Register a new account with an email",
                "Navigate to https://www.abuseipdb.com/account/api",
                "The API Key is listed under 'Keys'"
            ],
            'favIcon': "https://www.abuseipdb.com/favicon.ico",
            'logo': "https://www.abuseipdb.com/img/abuseipdb.png.pagespeed.ce.CI8T6WsXU7.png",
            'description': "AbuseIPDB is a project dedicated to helping combat the spread of hackers,"
                                "spammers, and abusive activity on the internet.\n"
                                "Our mission is to help make Web safer by providing a central blacklist for"
                                "webmasters, system administrators, and other interested parties to"
                                "report and find IP addresses that have been associated with malicious activity online."
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'confidenceminimum': 90,
        'checkaffiliates': True,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'api_key': "AbuseIPDB.com API key.",
        'confidenceminimum': "The minimium AbuseIPDB confidence level to require.",
        'checkaffiliates': "Apply checks to affiliates?",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR",
                "MALICIOUS_SUBNET", "MALICIOUS_NETBLOCK"]

    def lookupItem(self, resourceId, itemType, target):
        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.sf.debug("Checking maliciousness of " + target + " (" + itemType + ") with: " + cid)
                return self.resourceList(cid, target, itemType)
        return None

    # Look up 'list' type resources
    def resourceList(self, id, target, targetType):
        targetDom = ''
        # Get the base domain if we're supplied a domain
        if targetType == "domain":
            targetDom = self.sf.hostDomain(target, self.opts['_internettlds'])
            if not targetDom:
                return None

        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if id == cid:
                data = dict()
                url = malchecks[check]['url'].format(self.opts['confidenceminimum'])
                hdr = {
                    'Key': self.opts['api_key'],
                    'Accept': "text/plain"
                }
                data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                        useragent=self.opts['_useragent'], headers=hdr)
                if data['content'] is None:
                    self.sf.error("Unable to fetch " + url, False)
                    return None

                url = "https://www.abuseipdb.com/check/" + target

                # If we're looking at netblocks
                if targetType == "netblock":
                    iplist = list()
                    # Get the regex, replace {0} with an IP address matcher to
                    # build a list of IP.
                    # Cycle through each IP and check if it's in the netblock.
                    if 'regex' in malchecks[check]:
                        rx = malchecks[check]['regex'].replace("{0}", r"(\d+\.\d+\.\d+\.\d+)")
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
                                self.sf.debug(ip + " found within netblock/subnet " + target + " in " + check)
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
                    try:
                        rxDom = str(malchecks[check]['regex']).format(targetDom)
                        rxTgt = str(malchecks[check]['regex']).format(target)
                        for line in data['content'].split('\n'):
                            if (targetType == "domain" and re.match(rxDom, line, re.IGNORECASE)) or \
                                    re.match(rxTgt, line, re.IGNORECASE):
                                self.sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                                return url
                    except BaseException as e:
                        self.sf.debug("Error encountered parsing 2: " + str(e))
                        continue

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

        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return None
        if eventName == 'NETBLOCK_OWNER' and not self.opts.get('checknetblocks', False):
            return None
        if eventName == 'NETBLOCK_MEMBER' and not self.opts.get('checksubnets', False):
            return None

        for check in list(malchecks.keys()):
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
                text = f"{check} [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_abuseipdb class
