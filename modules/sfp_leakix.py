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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_leakix(SpiderFootPlugin):

    meta = {
        'name': "LeakIX",
        'summary': "Search LeakIX for host data leaks, open ports, software and geoip.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://leakix.net/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://leakix.net/api-documentation"
            ],
            'apiKeyInstructions': [
                "Visit https://leakix.net/",
                "Register a free account",
                "Go to your 'Settings'",
                "Click on 'API key'",
                "Click on 'Reset key' to generate a new key"
            ],
            'favIcon': "https://leakix.net/public/img/favicon.png",
            'logo': "https://leakix.net/public/img/logoleakix-v1.png",
            'description': "LeakIX provides insights into devices and servers that are compromised "
            "and compromised database schemas online.\n"
            "In this scope we inspect found services for weak credentials.",
        }
    }

    # Default options
    opts = {
        'api_key': "",
        'delay': 1,
        "verify": True,
    }

    # Option descriptions
    optdescs = {
        'api_key': "LeakIX API key",
        'delay': 'Delay between requests, in seconds.',
        "verify": "Verify discovered hostnames are valid by checking if they still resolve.",
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
        return ["IP_ADDRESS", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO", "TCP_PORT_OPEN",
                "OPERATING_SYSTEM", "SOFTWARE_USED", "WEBSERVER_BANNER",
                "LEAKSITE_CONTENT", "INTERNET_NAME"]

    # Query host
    # https://leakix.net/api-documentation
    def queryApi(self, qryType, qry):
        headers = {
            "Accept": "application/json",
            "api-key": self.opts["api_key"]
        }
        res = self.sf.fetchUrl(
            'https://leakix.net/' + qryType + '/' + qry,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    def parseAPIResponse(self, res):
        if res['code'] == '404':
            self.debug("Host not found")
            return None

        # Future proofing - LeakIX does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by LeakIX")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from LeakIX")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        ports = list()
        hosts = list()
        oses = list()
        softwares = list()
        ips = list()
        banners = list()
        locs = list()

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        if self.opts['api_key'] == "":
            self.debug("You enabled sfp_leakix but did not set an API key, results are limited")
        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName in ["IP_ADDRESS", "DOMAIN_NAME"]:
            if eventName == "IP_ADDRESS":
                data = self.queryApi("host", eventData)
            if eventName == "DOMAIN_NAME":
                data = self.queryApi("domain", eventData)

            if data is None:
                self.debug("No information found for host " + eventData)
                return

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

            services = data.get("Services")

            if services:
                for service in services:
                    ip = service.get('ip')
                    if ip and eventName != "IP_ADDRESS" and self.sf.validIP(ip) and ip not in ips:
                        evt = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                        self.notifyListeners(evt)
                        ips.append(ip)
                    port = service.get('port')
                    if port and eventData + ":" + port not in ports:
                        evt = SpiderFootEvent("TCP_PORT_OPEN", eventData + ':' + port, self.__name__, event)
                        self.notifyListeners(evt)
                        ports.append(eventData + ":" + port)
                    hostname = service.get('hostname')
                    if hostname and eventName == "DOMAIN_NAME" and self.getTarget().matches(hostname) and hostname not in hosts:
                        if self.opts["verify"] and not self.sf.resolveHost(hostname) and not self.sf.resolveHost6(hostname):
                            self.debug(f"Host {hostname} could not be resolved")
                            evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                        else:
                            evt = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
                        self.notifyListeners(evt)
                        hosts.append(hostname)
                    headers = service.get('headers')
                    if headers:
                        servers = headers.get('Server')
                        if servers:
                            for server in servers:
                                if server and server not in banners:
                                    evt = SpiderFootEvent('WEBSERVER_BANNER', server, self.__name__, event)
                                    self.notifyListeners(evt)
                                    banners.append(server)

                    geoip = service.get('geoip')
                    if geoip:
                        location = ', '.join([_f for _f in [geoip.get('city_name'), geoip.get('region_name'), geoip.get('country_name')] if _f])
                        if location and location not in locs:
                            evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                            self.notifyListeners(evt)
                            locs.append(location)

                    software = service.get('software')
                    if software:
                        software_version = ' '.join([_f for _f in [software.get('name'), software.get('version')] if _f])
                        if software_version and software_version not in softwares:
                            evt = SpiderFootEvent("SOFTWARE_USED", software_version, self.__name__, event)
                            self.notifyListeners(evt)
                            softwares.append(software_version)

                        os = software.get('os')
                        if os and os not in oses:
                            evt = SpiderFootEvent('OPERATING_SYSTEM', os, self.__name__, event)
                            self.notifyListeners(evt)
                            oses.append(os)

            leaks = data.get("Leaks")

            if leaks:
                for leak in leaks:
                    leak_protocol = leak.get('type')
                    hostname = leak.get('hostname')
                    # If protocol is web, our hostname not empty and is not an IP ,
                    # and doesn't belong to our target, discard ( happens when sharing Hosting/CDN IPs )
                    if leak_protocol == "web" and hostname and not self.sf.validIP(hostname) and not self.getTarget().matches(hostname):
                        continue
                    leak_data = leak.get('data')
                    if leak_data:
                        evt = SpiderFootEvent("LEAKSITE_CONTENT", leak_data, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_leakix class
