# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_talosintel
# Purpose:      Check if a netblock or IP address is malicious according to
#               TalosIntelligence.
#
# Author:       steve@binarypool.com
#
# Created:     26/03/2019
# Copyright:   (c) Steve Micallef, 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_talosintel(SpiderFootPlugin):

    meta = {
        'name': "Talos Intelligence",
        'summary': "Check if a netblock or IP address is malicious according to TalosIntelligence.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://talosintelligence.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://talosintelligence.com/vulnerability_info",
                "https://talosintelligence.com/reputation"
            ],
            'favIcon': "https://talosintelligence.com/assets/favicons/favicon-49c9b25776778ff43873cf5ebde2e1ffcd0747ad1042ac5a5306cdde3ffca8cd.ico",
            'logo': "https://talosintelligence.com/assets/favicons/favicon-49c9b25776778ff43873cf5ebde2e1ffcd0747ad1042ac5a5306cdde3ffca8cd.ico",
            'description': "Cisco Talos Incident Response provides a full suite of proactive and reactive services "
            "to help you prepare, respond and recover from a breach. "
            "With Talos IR, you have direct access to the same threat intelligence available "
            "to Cisco and world-class emergency response capabilities — "
            "in addition to more than 350 threat researchers for questions and analysis. "
            "Let our experts work with you to evaluate existing plans, develop a new plan, "
            "and provide rapid assistance when you need it most.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK",
        ]

    def queryBlacklist(self, target, targetType):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Talos Intelligence blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Talos Intelligence blacklist.")
                    return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('talosintel', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        # https://talosintelligence.com/documents/ip-blacklist redirects to:
        # https://snort.org/downloads/ip-block-list
        res = self.sf.fetchUrl(
            "https://snort.org/downloads/ip-block-list",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Talos Intelligence.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Talos Intelligence")
            self.errorState = True
            return None

        self.sf.cachePut("talosintel", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from Talos Intelligence

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for ip in blacklist.split('\n'):
            ip = ip.strip()
            if ip.startswith('#'):
                continue
            if not self.sf.validIP(ip):
                continue
            ips.append(ip)

        return ips

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Talos Intelligence")

        if not self.queryBlacklist(eventData, targetType):
            return

        url = "https://snort.org/downloads/ip-block-list"
        text = f"Talos Intelligence [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_talosintel class
