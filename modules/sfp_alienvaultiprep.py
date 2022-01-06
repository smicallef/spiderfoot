# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_alienvaultiprep
# Purpose:     Check if an IP or netblock is malicious according to the AlienVault
#              IP Reputation database.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_alienvaultiprep(SpiderFootPlugin):

    meta = {
        'name': "AlienVault IP Reputation",
        'summary': "Check if an IP or netblock is malicious according to the AlienVault IP Reputation database.",
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cybersecurity.att.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cybersecurity.att.com/documentation/",
                "https://cybersecurity.att.com/resource-center",
                "https://success.alienvault.com/s/article/Can-I-use-the-OTX-IP-Reputation-List-as-a-blocklist",
            ],
            'favIcon': "https://cdn-cybersecurity.att.com/images/uploads/logos/att-globe.svg",
            'logo': "https://cdn-cybersecurity.att.com/images/uploads/logos/att-business-web.svg",
            'description': "Looking at security through new eyes.\n"
            "AT&T Business and AlienVault have joined forces to create AT&T Cybersecurity, "
            "with a vision to bring together the people, process, and technology "
            "that help businesses of any size stay ahead of threats.",
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
            "AFFILIATE_IPADDR",
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER"
        ]

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
                self.debug(f"IP address {target} found in AlienVault IP Reputation Database blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in AlienVault IP Reputation Database blacklist.")
                    return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.sf.cacheGet('alienvaultiprep', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://reputation.alienvault.com/reputation.generic",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from AlienVault IP Reputation Database.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from AlienVault IP Reputation Database")
            self.errorState = True
            return None

        self.sf.cachePut("alienvaultiprep", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from AlienVault IP Reputation Database

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for ip in blacklist.split('\n'):
            ip = ip.strip().split(" #")[0]
            if ip.startswith('#'):
                continue
            if not self.sf.validIP(ip):
                continue
            ips.append(ip)

        return ips

    # Handle events sent to this module
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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with AlienVault IP Reputation Database")

        if not self.queryBlacklist(eventData, targetType):
            return

        url = "https://reputation.alienvault.com/reputation.generic"
        text = f"AlienVault IP Reputation Database [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_alienvaultiprep class
