# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_bgpview
# Purpose:     Query BGPView API - https://bgpview.docs.apiary.io/
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-03
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bgpview(SpiderFootPlugin):

    meta = {
        'name': "BGPView",
        'summary': "Obtain network information from BGPView API.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://bgpview.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://bgpview.docs.apiary.io/#",
                "https://bgpview.docs.apiary.io/api-description-document"
            ],
            'favIcon': "https://bgpview.io/favicon-32x32.png",
            'logo': "https://bgpview.io/assets/logo.png",
            'description': "BGPView is a simple API allowing consumers to view all sort of analytics data about the current state and structure of the internet.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'IPV6_ADDRESS',
            'BGP_AS_MEMBER',
            'NETBLOCK_MEMBER',
            'NETBLOCKV6_MEMBER'
        ]

    def producedEvents(self):
        return [
            'BGP_AS_MEMBER',
            'NETBLOCK_MEMBER',
            'NETBLOCKV6_MEMBER',
            'PHYSICAL_ADDRESS',
            'RAW_RIR_DATA'
        ]

    def queryAsn(self, qry):
        res = self.sf.fetchUrl("https://api.bgpview.io/asn/" + qry.replace('AS', ''),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            json_data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from BGPView: {e}")
            return None

        if json_data.get('status') != 'ok':
            self.debug("No results found for ASN " + qry)
            return None

        data = json_data.get('data')

        if not data:
            self.debug("No results found for ASN " + qry)
            return None

        return data

    def queryIp(self, qry):
        res = self.sf.fetchUrl("https://api.bgpview.io/ip/" + qry,
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            json_data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from BGPView: {e}")
            return None

        if json_data.get('status') != 'ok':
            self.debug("No results found for IP address " + qry)
            return None

        data = json_data.get('data')

        if not data:
            self.debug("No results found for IP address " + qry)
            return None

        return data

    def queryNetblock(self, qry):
        res = self.sf.fetchUrl("https://api.bgpview.io/prefix/" + qry,
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            json_data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from BGPView: {e}")
            return None

        if json_data.get('status') != 'ok':
            self.debug("No results found for netblock " + qry)
            return None

        data = json_data.get('data')

        if not data:
            self.debug("No results found for netblock " + qry)
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'BGP_AS_MEMBER':
            data = self.queryAsn(eventData)

            if not data:
                self.info("No results found for ASN " + eventData)
                return

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            address = data.get('owner_address')

            if not address:
                return

            evt = SpiderFootEvent('PHYSICAL_ADDRESS', ', '.join([_f for _f in address if _f]), self.__name__, event)
            self.notifyListeners(evt)

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            data = self.queryNetblock(eventData)

            if not data:
                self.info("No results found for netblock " + eventData)
                return

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            address = data.get('owner_address')

            if not address:
                return

            evt = SpiderFootEvent('PHYSICAL_ADDRESS', ', '.join([_f for _f in address if _f]), self.__name__, event)
            self.notifyListeners(evt)

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            data = self.queryIp(eventData)

            if not data:
                self.info("No results found for IP address " + eventData)
                return

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            prefixes = data.get('prefixes')

            if not prefixes:
                self.info("No prefixes found for IP address " + eventData)
                return

            for prefix in prefixes:
                p = prefix.get('prefix')
                if not p:
                    continue

                if not prefix.get('asn'):
                    continue

                asn = prefix.get('asn').get('asn')
                if not asn:
                    continue

                self.info(f"Netblock found: {p} ({asn})")
                evt = SpiderFootEvent("BGP_AS_MEMBER", str(asn), self.__name__, event)
                self.notifyListeners(evt)

                if self.sf.validIpNetwork(p):
                    if ":" in p:
                        evt = SpiderFootEvent("NETBLOCKV6_MEMBER", p, self.__name__, event)
                    else:
                        evt = SpiderFootEvent("NETBLOCK_MEMBER", p, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_bgpview class
