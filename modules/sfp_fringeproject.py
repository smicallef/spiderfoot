# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_fringeproject
# Purpose:     Query Fringe Project API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-10-03
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re

import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_fringeproject(SpiderFootPlugin):
    """Fringe Project:Investigate,Footprint,Passive:Search Engines::Obtain network information from Fringe Project API."""

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
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    def producedEvents(self):
        return ['INTERNET_NAME', 'LINKED_URL_INTERNAL', 'DOMAIN_NAME',
                'TCP_PORT_OPEN', 'SOFTWARE_USED', 'RAW_RIR_DATA']

    def query(self, qry):
        params = {
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        res = self.sf.fetchUrl('https://api.fringeproject.com/api/search?' + urllib.parse.urlencode(params),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            json_data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug("Error processing JSON response from Fringe Project: " + str(e))
            return None

        data = json_data.get('results')

        if not data:
            self.sf.debug("No results found for " + qry)
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if srcModuleName == 'sfp_fringeproject':
            self.sf.debug("Ignoring " + eventData + ", from self.")
            return None

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        data = self.query(eventData)

        if not data:
            self.sf.info("No results found for " + eventData)
            return None

        e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(e)

        hosts = list()

        for result in data:
            data_type = result.get('type')

            if data_type not in ['url', 'hostname']:
                self.sf.debug('Unknown result data type: ' + data_type)
                continue

            value = result.get('value')

            if not value:
                continue

            if data_type == 'hostname':
                if not self.getTarget().matches(value, includeChildren=True, includeParents=True):
                    continue

                hosts.append(value)

            if data_type == 'url':
                host = self.sf.urlFQDN(value.lower())

                if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                    continue

                hosts.append(host)

                evt = SpiderFootEvent('LINKED_URL_INTERNAL', value, self.__name__, event)
                self.notifyListeners(evt)

            tags = result.get('tags')

            if not tags:
                continue

            for tag in tags:
                try:
                    port = re.findall(r'^port:([0-9]+)', tag)
                except BaseException as e:
                    self.sf.debug("Didn't get sane data from FringeProject.")
                    continue

                if len(port) > 0:
                    evt = SpiderFootEvent('TCP_PORT_OPEN', value + ':' + str(port[0]), self.__name__, event)
                    self.notifyListeners(evt)

        for host in set(hosts):
            evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
            self.notifyListeners(evt)
            if self.sf.isDomain(host, self.opts['_internettlds']):
                evt = SpiderFootEvent('DOMAIN_NAME', host, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_fringeproject class
