# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_fullhunt
# Purpose:     Identify domain attack surface using FullHunt API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-26
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_fullhunt(SpiderFootPlugin):

    meta = {
        'name': "FullHunt",
        'summary': "Identify domain attack surface using FullHunt API.",
        'flags': ['apikey'],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://fullhunt.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api-docs.fullhunt.io/",
            ],
            'apiKeyInstructions': [
                "Visit https://fullhunt.io/",
                "Register a free account",
                "Navigate to https://fullhunt.io/user/settings/",
                "Your API key is listed under 'API Access'"
            ],
            'favIcon': "https://fullhunt.io/static/theme/images/logo/favicon.ico",
            'logo': "https://fullhunt.io/static/theme/images/logo/Icon.png",
            'description': "Discover, monitor, and secure your attack surface. "
            "FullHunt delivers the best platform in the market for attack surface security."
        }
    }

    opts = {
        "api_key": "",
    }

    optdescs = {
        "api_key": "FullHunt API key.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
        ]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME_UNRESOLVED",
            "TCP_PORT_OPEN",
            "PROVIDER_DNS",
            "PROVIDER_MAIL",
        ]

    def queryDomainDetails(self, qry):
        """Search for hosts on a domain.

        Args:
            qry (str): domain name

        Returns:
            dict: search results
        """
        headers = {
            'X-API-KEY': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            f"https://fullhunt.io/api/v1/domain/{qry}/details",
            timeout=30,
            headers=headers,
            useragent=self.opts['_useragent']
        )

        return self.parseApiResponse(res)

    def parseApiResponse(self, res):
        if not res:
            return None

        if res['code'] == "400":
            self.error("Bad Request -- Your request is invalid.")
            return None

        if res['code'] == "401":
            self.error("Unauthorized -- Your API key is wrong.")
            return None

        if res['code'] == "403":
            self.error("Forbidden -- The requested resource is forbidden.")
            return None

        if res['code'] == "404":
            self.error("Not Found -- The requested resource could not be found.")
            return None

        if res['code'] == "429":
            self.error("Too Many Requests -- You are sending too many requests.")
            return None

        try:
            results = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return results.get('hosts')

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        res = self.queryDomainDetails(eventData)

        if not res:
            self.debug(f"Found no results for {eventData}")
            return

        e = SpiderFootEvent("RAW_RIR_DATA", str(res), self.__name__, event)
        self.notifyListeners(e)

        hosts = list()
        name_servers = list()
        mail_servers = list()

        for record in res:
            host = record.get('host')

            if not host:
                continue

            hosts.append(host)

            dns = record.get('dns')
            if dns:
                mx = dns.get('mx')
                if mx:
                    for mail_server in mx:
                        mail_servers.append(mail_server.rstrip("."))

                ns = dns.get('ns')
                if ns:
                    for name_server in ns:
                        name_servers.append(name_server.rstrip("."))

                cname = dns.get('cname')
                if cname:
                    for c in cname:
                        hosts.append(c.rstrip("."))

            network_ports = record.get('network_ports')
            if network_ports:
                for port in network_ports:
                    e = SpiderFootEvent("TCP_PORT_OPEN", f"{host}:{port}", self.__name__, event)
                    self.notifyListeners(e)

        for host in set(mail_servers):
            if not host:
                continue

            hosts.append(host)

            e = SpiderFootEvent("PROVIDER_MAIL", host, self.__name__, event)
            self.notifyListeners(e)

        for host in set(name_servers):
            if not host:
                continue

            hosts.append(host)

            e = SpiderFootEvent("PROVIDER_DNS", host, self.__name__, event)
            self.notifyListeners(e)

        for host in set(hosts):
            if not host:
                continue

            if host in self.results:
                continue

            self.results[host] = True

            if self.getTarget().matches(host, includeChildren=True):
                evt_type = "INTERNET_NAME"
            else:
                evt_type = "AFFILIATE_INTERNET_NAME"

            if not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                self.debug(f"Host {host} could not be resolved")
                evt_type += "_UNRESOLVED"

            evt = SpiderFootEvent(evt_type, host, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_fullhunt class
