# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_opnenic
# Purpose:     SpiderFoot plug-in for resolving host names on the OpenNIC
#              alternative DNS system.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-16
# Copyright:   (c) bcoles 2021
# Licence:     MIT
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_opennic(SpiderFootPlugin):

    meta = {
        'name': "OpenNIC DNS",
        'summary': "Resolves host names in the OpenNIC alternative DNS system.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["DNS"],
        'dataSource': {
            'website': "https://www.opennic.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://wiki.opennic.org/",
                "https://servers.opennic.org",
            ],
            'description': "An organization of hobbyists who run an alternative DNS network, "
            "also provides access to domains not administered by ICANN."
        }
    }

    opts = {
        'checkaffiliates': True,
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME_UNRESOLVED",
        ]

    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
        ]

    def queryOpenNIC(self, qaddr):
        res = dns.resolver.Resolver()
        # https://servers.opennicproject.org/
        res.nameservers = [
            "192.3.165.37",
            "35.211.96.150",
            "51.89.88.77",
            "94.247.43.254",
            "138.197.140.189"
        ]

        try:
            return res.resolve(qaddr)
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")

        return None

    def tlds(self):
        """Valid OpenNIC top-level domains.

        Returns:
            list: OpenNIC TLDs (and peer TLDs).
        """
        return [
            'bbs',
            'chan',
            'cyb',
            'dyn',
            'epic',
            'free',
            'geek',
            'glue',
            'gopher',
            'indy',
            'libre',
            'neo',
            'null',
            'o',
            'oss',
            'oz',
            'parody',
            'pirate',

            # Peers
            'bazar',
            'bit',
            'coin',
            'emc',
            'fur',
            'ku',
            'lib',
            'te',
            'ti',
            'uu',
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventData.split('.')[-1] not in self.tlds():
            return

        affiliate = False

        if "AFFILIATE" in eventName:
            if not self.opts.get('checkaffiliates', False):
                return
            affiliate = True

        addrs = self.sf.normalizeDNS(self.queryOpenNIC(eventData))

        if not addrs:
            return

        self.debug(f"OpenNIC resolved {eventData} to addresses: {addrs}")

        for addr in set(addrs):
            if self.sf.validIP(addr):
                if affiliate and not self.getTarget().matches(addr, includeParents=True):
                    evt = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                else:
                    evt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)

                self.notifyListeners(evt)
            elif self.sf.validIP6(addr):
                if affiliate and not self.getTarget().matches(addr, includeParents=True):
                    evt = SpiderFootEvent("AFFILIATE_IPV6_ADDRESS", addr, self.__name__, event)
                else:
                    evt = SpiderFootEvent("IPV6_ADDRESS", addr, self.__name__, event)

                self.notifyListeners(evt)
            else:
                continue

# End of sfp_opennic class
