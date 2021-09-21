# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_blocklistde
# Purpose:      Check if a netblock or IP is malicious according to blocklist.de.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_blocklistde(SpiderFootPlugin):

    meta = {
        'name': "blocklist.de",
        'summary': "Check if a netblock or IP is malicious according to blocklist.de.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.blocklist.de/en/index.html",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.blocklist.de/en/api.html",
                "http://www.blocklist.de/en/rbldns.html",
                "http://www.blocklist.de/en/httpreports.html",
                "http://www.blocklist.de/en/export.html",
                "http://www.blocklist.de/en/delist.html?ip="
            ],
            'favIcon': "http://www.blocklist.de/templates/css/logo_web-size.jpg",
            'logo': "http://www.blocklist.de/templates/css/logo_web-size.jpg",
            'description': "www.blocklist.de is a free and voluntary service provided by a Fraud/Abuse-specialist, "
            "whose servers are often attacked via SSH-, Mail-Login-, FTP-, Webserver- and other services.\n"
            "The mission is to report any and all attacks to the respective abuse departments of the infected PCs/servers, "
            "to ensure that the responsible provider can inform their customer about the infection and disable the attacker."
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

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
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK"
        ]

    def queryBlacklist(self, target, targetType):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.sf.debug(f"IP address {target} found in blocklist.de blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.sf.debug(f"IP address {ip} found within netblock/subnet {target} in blocklist.de blacklist.")
                    return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('blocklistde', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://lists.blocklist.de/lists/all.txt",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.sf.error(f"Unexpected HTTP response code {res['code']} from blocklist.de.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.error("Received no content from blocklist.de")
            self.errorState = True
            return None

        self.sf.cachePut("blocklistde", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from blocklist.de

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

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            evtType = 'MALICIOUS_IPADDR'
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_NETBLOCK'
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_SUBNET'
        else:
            return

        self.sf.debug(f"Checking maliciousness of {eventData} ({eventName}) with blocklist.de")

        if self.queryBlacklist(eventData, targetType):
            url = "https://lists.blocklist.de/lists/all.txt"
            text = f"blocklist.de [{eventData}]\n<SFURL>{url}</SFURL>"
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_blocklistde class
