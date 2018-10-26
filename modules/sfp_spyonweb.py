# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_spyonweb
# Purpose:      SpiderFoot plug-in to search SpyOnWeb for hosts sharing the
#               same IP address, Google Analytics code, or Google Adsense code.
#
# Author:      Brendan Coles <bcoles@gmail.com>
#
# Created:     2018-10-25
# Copyright:   (c) Brendan Coles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
import datetime
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_spyonweb(SpiderFootPlugin):
    """SpyOnWeb:Footprint,Investigate,Passive:Passive DNS:apikey:Search SpyOnWeb for hosts sharing the same IP address, Google Analytics code, or Google Adsense code."""

    # Default options
    opts = {
        'api_key': '',
        'limit': 100,
        'timeout': 30,
        'maxage': 1095,   # 3 years
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'api_key': "SpyOnWeb API key.",
        'limit': "Maximum number of results to fetch.",
        'timeout': "Query timeout, in seconds.",
        'maxage': "The maximum age of the data returned, in days, in order to be considered valid.",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
    }

    cohostcount = 0
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "SpyOnWeb"
        self.results = dict()
        self.cohostcount = 0                                                                                                                                                                                       

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Verify a host resolves to an IP
    def validateIP(self, host, ip):
        try:
            addrs = socket.gethostbyname_ex(host)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

        for addr in addrs:
            if type(addr) == list:
                for a in addr:
                    if str(a) == ip:
                        return True
            else:
                if str(addr) == ip:
                    return True
        return False

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME', 'WEB_ANALYTICS_ID']

    # What events this module produces
    def producedEvents(self):
        return ['CO_HOSTED_SITE', 'INTERNET_NAME', 'AFFILIATE_DOMAIN', 'WEB_ANALYTICS_ID']

    # Retrieve hosts with the specified Google Analytics ID
    # https://api.spyonweb.com/v1/docs
    def queryGoogleAnalytics(self, qry, limit=100):
        url = "https://api.spyonweb.com/v1/analytics/" + qry
        url += "?limit=" + str(limit)
        url += "&access_token=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No results found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        status = data.get('status')
        if not status == 'found':
            self.sf.info("No results found for " + qry)
            return None

        if 'result' not in data:
            self.sf.info("No results found for " + qry)
            return None

        if 'analytics' not in data['result']:
            self.sf.info("No results found for " + qry)
            return None

        if qry not in data['result']['analytics']:
            self.sf.info("No results found for " + qry)
            return None

        items = data['result']['analytics'][qry].get('items')

        if not items:
            self.sf.debug("No results found for " + qry)
            return None

        self.sf.info("Retrieved " + str(len(items)) + " results")

        return items

    # Retrieve hosts with the specified Google AdSense ID
    # https://api.spyonweb.com/v1/docs
    def queryGoogleAdsense(self, qry, limit=100):
        url = "https://api.spyonweb.com/v1/adsense/" + qry
        url += "?limit=" + str(limit)
        url += "&access_token=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No results found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        status = data.get('status')
        if not status == 'found':
            self.sf.info("No results found for " + qry)
            return None

        if 'result' not in data:
            self.sf.info("No results found for " + qry)
            return None

        if 'adsense' not in data['result']:
            self.sf.info("No results found for " + qry)
            return None

        if qry not in data['result']['adsense']:
            self.sf.info("No results found for " + qry)
            return None

        items = data['result']['adsense'][qry].get('items')

        if not items:
            self.sf.debug("No results found for " + qry)
            return None

        self.sf.info("Retrieved " + str(len(items)) + " results")

        return items

    # Retrieve hosts on the specified IP address
    # https://api.spyonweb.com/v1/docs
    def queryIP(self, qry, limit=100):
        url = "https://api.spyonweb.com/v1/ip/" + qry
        url += "?limit=" + str(limit)
        url += "&access_token=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No results found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        status = data.get('status')
        if not status == 'found':
            self.sf.info("No results found for " + qry)
            return None

        if 'result' not in data:
            self.sf.info("No results found for " + qry)
            return None

        if 'ip' not in data['result']:
            self.sf.info("No results found for " + qry)
            return None

        if qry not in data['result']['ip']:
            self.sf.info("No results found for " + qry)
            return None

        items = data['result']['ip'][qry].get('items')

        if not items:
            self.sf.debug("No results found for " + qry)
            return None

        self.sf.info("Retrieved " + str(len(items)) + " results")

        return items

    # Retrieve Google Analytics and Google AdSense IDs for the specified domain
    # https://api.spyonweb.com/v1/docs
    def querySummary(self, qry, limit=100):
        url = "https://api.spyonweb.com/v1/summary/" + qry
        url += "?limit=" + str(limit)
        url += "&access_token=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No results found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        status = data.get('status')
        if not status == 'found':
            self.sf.info("No results found for " + qry)
            return None

        if 'result' not in data:
            self.sf.info("No results found for " + qry)
            return None

        if 'summary' not in data['result']:
            self.sf.info("No results found for " + qry)
            return None

        if qry not in data['result']['summary']:
            self.sf.info("No results found for " + qry)
            return None

        items = data['result']['summary'][qry].get('items')

        if not items:
            self.sf.debug("No results found for " + qry)
            return None

        self.sf.info("Retrieved " + str(len(items)) + " results")

        return items

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_spyonweb but did not set an API key!", False)
            self.errorState = True
            return None

        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])

        # Find Google AdSense IDs and Google Analytics IDs for the specified domain
        if eventName in [ 'INTERNET_NAME', 'DOMAIN_NAME' ]:
            data = self.querySummary(eventData, limit=self.opts['limit'])

            if data is None:
                self.sf.info("No data found for " + eventData)
                return None

            google_adsense = data.get('adsense')
            if google_adsense:
                for r in google_adsense.keys():
                    evt = SpiderFootEvent("WEB_ANALYTICS_ID", "Google AdSense: " + r, self.__name__, event)
                    self.notifyListeners(evt)

            google_analytics = data.get('analytics')
            if google_analytics:
                for r in google_analytics.keys():
                    evt = SpiderFootEvent("WEB_ANALYTICS_ID", "Google Analytics: " + r, self.__name__, event)
                    self.notifyListeners(evt)

        # Find affiliate domains for the specified Google AdSense ID or Google Analytics ID
        if eventName in [ 'WEB_ANALYTICS_ID' ]:
            network = eventData.split(": ")[0]
            analytics_id = eventData.split(": ")[1]

            data = dict()
            if network == 'Google AdSense':
                data = self.queryGoogleAdsense(analytics_id, limit=self.opts['limit'])
            elif network == 'Google Analytics':
                data = self.queryGoogleAnalytics(analytics_id, limit=self.opts['limit'])
            else:
                return None

            if data is None:
                self.sf.info("No data found for " + eventData)
                return None

            for r in data.keys():
                last_seen = int(datetime.datetime.strptime(data[r], '%Y-%m-%d').strftime('%s')) * 1000

                if last_seen < agelimit:                                                                                                                                                                           
                    self.sf.debug("Record found too old, skipping.")
                    continue

                evt = SpiderFootEvent("AFFILIATE_DOMAIN", r, self.__name__, event)
                self.notifyListeners(evt)

        # Find co-hosts on the same IP address
        if eventName in [ 'IP_ADDRESS' ]:
            data = self.queryIP(eventData, limit=self.opts['limit'])

            if data is None:
                self.sf.info("No data found for " + eventData)
                return None

            cohostcount = 0

            for co in data.keys():
                last_seen = int(datetime.datetime.strptime(data[co], '%Y-%m-%d').strftime('%s')) * 1000

                if last_seen < agelimit:
                    self.sf.debug("Record found too old, skipping.")
                    continue

                if self.opts['verify'] and not self.validateIP(co, eventData):
                    self.sf.debug("Host " + co + " no longer resolves to " + eventData)
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(co, includeParents=True):
                        evt = SpiderFootEvent("INTERNET_NAME", co, self.__name__, event)
                        self.notifyListeners(evt)
                        continue

                if self.cohostcount < self.opts['maxcohost']:
                    evt = SpiderFootEvent("CO_HOSTED_SITE", co, self.__name__, event)
                    self.notifyListeners(evt)
                    self.cohostcount += 1

# End of sfp_spyonweb class
