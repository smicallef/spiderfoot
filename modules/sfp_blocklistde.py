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

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
        ]

    def queryBlacklist(self, target, targetType):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in blocklist.de blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in blocklist.de blacklist.")
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
            self.error(f"Unexpected HTTP response code {res['code']} from blocklist.de.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from blocklist.de")
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
            if not self.sf.validIP(ip) and not self.sf.validIP6(ip):
                continue
            ips.append(ip)

        return ips

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            targetType = 'ip'
            malicious_type = 'MALICIOUS_IPADDR'
            blacklist_type = 'BLACKLISTED_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            malicious_type = 'MALICIOUS_AFFILIATE_IPADDR'
            blacklist_type = 'BLACKLISTED_AFFILIATE_IPADDR'
        elif eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            malicious_type = 'MALICIOUS_NETBLOCK'
            blacklist_type = 'BLACKLISTED_NETBLOCK'
        elif eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            malicious_type = 'MALICIOUS_SUBNET'
            blacklist_type = 'BLACKLISTED_SUBNET'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with blocklist.de")

        if self.queryBlacklist(eventData, targetType):
            # https://www.blocklist.de/en/search.html?ip=<ip>
            url = "https://lists.blocklist.de/lists/all.txt"
            text = f"blocklist.de [{eventData}]\n<SFURL>{url}</SFURL>"

            evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
            self.notifyListeners(evt)

            evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_blocklistde class
