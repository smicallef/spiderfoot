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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_bgpview(SpiderFootPlugin):
    """BGPView:Investigate,Footprint,Passive:Search Engines::Obtain network information from BGPView API."""

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
        return ['IP_ADDRESS', 'IPV6_ADDRESS', 'BGP_AS_MEMBER', 'NETBLOCK_MEMBER']

    def producedEvents(self):
        return ['BGP_AS_MEMBER', 'NETBLOCK_MEMBER',
                'PHYSICAL_ADDRESS', 'RAW_RIR_DATA']

    def queryAsn(self, qry):
        res = self.sf.fetchUrl("https://api.bgpview.io/asn/" + qry.replace('AS', ''),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            json_data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug("Error processing JSON response from BGPView: " + str(e))
            return None

        if not json_data.get('status') == 'ok':
            self.sf.debug("No results found for ASN " + qry)
            return None

        data = json_data.get('data')

        if not data:
            self.sf.debug("No results found for ASN " + qry)
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
        except BaseException as e:
            self.sf.debug("Error processing JSON response from BGPView: " + str(e))
            return None

        if not json_data.get('status') == 'ok':
            self.sf.debug("No results found for IP address " + qry)
            return None

        data = json_data.get('data')

        if not data:
            self.sf.debug("No results found for IP address " + qry)
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
        except BaseException as e:
            self.sf.debug("Error processing JSON response from BGPView: " + str(e))
            return None

        if not json_data.get('status') == 'ok':
            self.sf.debug("No results found for netblock " + qry)
            return None

        data = json_data.get('data')

        if not data:
            self.sf.debug("No results found for netblock " + qry)
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        if eventName == 'BGP_AS_MEMBER':
            data = self.queryAsn(eventData)

            if not data:
                self.sf.info("No results found for ASN " + eventData)
                return None

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            address = data.get('owner_address')

            if not address:
                return None

            evt = SpiderFootEvent('PHYSICAL_ADDRESS', ', '.join([_f for _f in address if _f]), self.__name__, event)
            self.notifyListeners(evt)

        if eventName == 'NETBLOCK_MEMBER':
            data = self.queryNetblock(eventData)

            if not data:
                self.sf.info("No results found for netblock " + eventData)
                return None

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            address = data.get('owner_address')

            if not address:
                return None

            evt = SpiderFootEvent('PHYSICAL_ADDRESS', ', '.join([_f for _f in address if _f]), self.__name__, event)
            self.notifyListeners(evt)

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            data = self.queryIp(eventData)

            if not data:
                self.sf.info("No results found for IP address " + eventData)
                return None

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            prefixes = data.get('prefixes')

            if not prefixes:
                self.sf.info("No prefixes found for IP address " + eventData)
                return None

            for prefix in prefixes:
                p = prefix.get('prefix')
                if not p:
                    continue

                # Not supporting IPv6 prefixes
                if ":" in p:
                    continue
                if not prefix.get('asn'):
                    continue
                asn = prefix.get('asn').get('asn')
                if not asn:
                    continue

                self.sf.info("Netblock found: " + p + " (" + str(asn) + ")")
                evt = SpiderFootEvent("BGP_AS_MEMBER", str(asn), self.__name__, event)
                self.notifyListeners(evt)

                if self.sf.validIpNetwork(p):
                    evt = SpiderFootEvent("NETBLOCK_MEMBER", p, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_bgpview class
