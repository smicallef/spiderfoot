# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_leakix
# Purpose:     Search LeakIX for host data leaks, open ports, software and geoip.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-06-16
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_leakix(SpiderFootPlugin):
    """LeakIX:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Search LeakIX for host data leaks, open ports, software and geoip."""

    # Default options
    opts = {
        'delay': 1,
    }

    # Option descriptions
    optdescs = {
        'delay': 'Delay between requests, in seconds.',
    }

    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO", "TCP_PORT_OPEN",
                "OPERATING_SYSTEM", "SOFTWARE_USED", "WEBSERVER_BANNER",
                "LEAKSITE_CONTENT"]

    # Query host
    # https://leakix.net/api-documentation
    def queryHost(self, qry):
        headers = {
            "Accept" : "application/json"
        }
        res = self.sf.fetchUrl(
          'https://leakix.net/host/' + qry,
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    def parseAPIResponse(self, res):
        if res['code'] == '404':
            self.sf.debug("Host not found")
            return None

        # Future proofing - LeakIX does not implement rate limiting
        if res['code'] == '429':
            self.sf.error("You are being rate-limited by LeakIX", False)
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from LeakIX", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventName in ["IP_ADDRESS"]:
            data = self.queryHost(eventData)

            if data is None:
                self.sf.debug("No information found for host " + eventData)
                return None

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

            services = data.get("Services")

            if services:
                for service in services:
                    port = service.get('port')
                    if port:
                        evt = SpiderFootEvent("TCP_PORT_OPEN", eventData + ':' + port, self.__name__, event)
                        self.notifyListeners(evt)

                    headers = service.get('headers')
                    if headers:
                        servers = headers.get('Server')
                        if servers:
                            for server in servers:
                                if server:
                                    evt = SpiderFootEvent('WEBSERVER_BANNER', server, self.__name__, event)
                                    self.notifyListeners(evt)

                    geoip = service.get('geoip')
                    if geoip:
                        location = ', '.join([_f for _f in [geoip.get('city_name'), geoip.get('region_name'), geoip.get('country_name')] if _f])
                        if location:
                            evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                            self.notifyListeners(evt)

                    software = service.get('software')
                    if software:
                        software_version = ' '.join([_f for _f in [software.get('name'), software.get('version')] if _f])
                        if software_version:
                            evt = SpiderFootEvent("SOFTWARE_USED", software_version, self.__name__, event)
                            self.notifyListeners(evt)

                        os = software.get('os')
                        if os:
                            evt = SpiderFootEvent('OPERATING_SYSTEM', os, self.__name__, event)
                            self.notifyListeners(evt)

            leaks = data.get("Leaks")

            if leaks:
                for leak in leaks:
                    leak_data = leak.get('data')
                    if leak_data:
                        evt = SpiderFootEvent("LEAKSITE_CONTENT", leak_data, self.__name__, event)
                        self.notifyListeners(evt)

        return None

# End of sfp_leakix class
