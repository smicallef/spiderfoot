# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_greensnow
# Purpose:     Checks if an IP address or netblock is malicious according to greensnow.co.
#
# Author:      steve@binarypool.com
#
# Created:     16/05/2020
# Copyright:   (c) Steve Micallef, 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_greensnow(SpiderFootPlugin):

    meta = {
        'name': "Greensnow",
        'summary': "Check if a netblock or IP address is malicious according to greensnow.co.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://greensnow.co/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://blocklist.greensnow.co/greensnow.txt",
                "https://greensnow.co/faq"
            ],
            'favIcon': "https://greensnow.co/favicon.ico",
            'logo': "https://greensnow.co/img/logo.png",
            'description': "GreenSnow is a team consisting of the best specialists in computer security, "
            "we harvest a large number of IPs from different computers located around the world. "
            "GreenSnow is comparable with SpamHaus.org for attacks of any kind except for spam. "
            "Our list is updated automatically and you can withdraw at any time your IP address if it has been listed.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliate IP addresses?",
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
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER',
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

    def query(self, qry, targetType):
        cid = "_greensnow"
        url = "https://blocklist.greensnow.co/greensnow.txt"

        data = dict()
        data["content"] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))

        if data["content"] is None:
            data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if data["code"] != "200":
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            if data["content"] is None:
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            self.sf.cachePut("sfmal_" + cid, data['content'])

        for line in data["content"].split('\n'):
            ip = line.strip().lower()

            if targetType == "netblock":
                try:
                    if IPAddress(ip) in IPNetwork(qry):
                        self.debug(f"{ip} found within netblock/subnet {qry} in greensnow.co list.")
                        return f"https://greensnow.co/view/{ip}"
                except Exception as e:
                    self.debug(f"Error encountered parsing: {e}")
                    continue

            if targetType == "ip":
                if qry.lower() == ip:
                    self.debug(f"{qry} found in greensnow.co list.")
                    return f"https://greensnow.co/view/{ip}"

        return None

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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with greensnow.co")

        url = self.query(eventData, targetType)

        if not url:
            return

        text = f"greensnow.co [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_greensnow class
