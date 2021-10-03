# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Name:         sfp_dnscommonsrv
# Purpose:      SpiderFoot plug-in for attempting to resolve through
#               brute-forcing common DNS SRV records.
#
# Author:      Michael Scherer <misc@zarb.org>
#
# Created:     22/08/2017
# Copyright:   (c) Michael Scherer 2017
# Licence:     GPL
# -----------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnscommonsrv(SpiderFootPlugin):

    meta = {
        'name': "DNS Common SRV",
        'summary': "Attempts to identify hostnames through brute-forcing common DNS SRV records.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"]
    }

    opts = {}

    optdescs = {}

    events = None

    commonsrv = [
        # LDAP/Kerberos, used for Active Directory
        # https://technet.microsoft.com/en-us/library/cc961719.aspx
        '_ldap._tcp',
        '_gc._msdcs',
        '_ldap._tcp.pdc._msdcs',
        '_ldap._tcp.gc._msdcs',
        '_kerberos._tcp.dc._msdcs',
        '_kerberos._tcp',
        '_kerberos._udp',
        '_kerberos-master._tcp',
        '_kerberos-master._udp',
        '_kpasswd._tcp',
        '_kpasswd._udp',
        '_ntp._udp',

        # SIP
        '_sip._tcp',
        '_sip._udp',
        '_sip._tls',
        '_sips._tcp',

        # STUN
        # https://tools.ietf.org/html/rfc5389
        '_stun._tcp',
        '_stun._udp',
        '_stuns._tcp',

        # TURN
        # https://tools.ietf.org/html/rfc5928
        '_turn._tcp',
        '_turn._udp',
        '_turns._tcp',

        # XMPP
        # http://xmpp.org/rfcs/rfc6120.html
        '_jabber._tcp',
        '_xmpp-client._tcp',
        '_xmpp-server._tcp'
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['INTERNET_NAME', 'DOMAIN_NAME']

    def producedEvents(self):
        return ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == "sfp_dnscommonsrv":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        eventDataHash = self.sf.hashstring(eventData)
        parentEvent = event

        if eventDataHash in self.events:
            return

        self.events[eventDataHash] = True

        res = dns.resolver.Resolver()
        if self.opts.get('_dnsserver', "") != "":
            res.nameservers = [self.opts['_dnsserver']]

        self.debug("Iterating through possible SRV records.")

        # Try resolving common names
        for srv in self.commonsrv:
            if self.checkForStop():
                return

            name = srv + "." + eventData

            # Skip hosts we've processed already
            if self.sf.hashstring(name) in self.events:
                continue

            try:
                answers = res.query(name, 'SRV')
            except Exception:
                answers = []

            if not answers:
                continue

            evt = SpiderFootEvent(
                "DNS_SRV",
                name,
                self.__name__,
                parentEvent
            )
            self.notifyListeners(evt)

            for a in answers:
                # Strip off the trailing .
                tgt_clean = a.target.to_text().rstrip(".")

                if self.getTarget().matches(tgt_clean):
                    evt_type = "INTERNET_NAME"
                else:
                    evt_type = "AFFILIATE_INTERNET_NAME"

                evt = SpiderFootEvent(
                    evt_type,
                    tgt_clean,
                    self.__name__,
                    parentEvent
                )
                self.notifyListeners(evt)

# End of sfp_dnscommonsrv class
