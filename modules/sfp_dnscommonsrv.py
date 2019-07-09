# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Name:         sfp_dnscommonsrv
# Purpose:      SpiderFoot plug-in for attempting to resolve through
#               brute-forcing common SRV record.
#
# Author:      Michael Scherer <misc@zarb.org>
#
# Created:     22/08/2017
# Copyright:   (c) Michael Scherer 2017
# Licence:     GPL
# -----------------------------------------------------------------------------

import dns.resolver
from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_dnscommonsrv(SpiderFootPlugin):
    """DNS Common SRV:Footprint,Investigate,Passive:DNS::Attempts to identify hostnames through common SRV."""

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    events = dict()

    commonsrv = [ # LDAP/Kerberos, used for Active Directory
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
                 '_xmpp-server._tcp']

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = dict()
        self.__dataSource__ = "DNS"

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', 'DOMAIN_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName +
                      ", from " + srcModuleName)

        if srcModuleName == "sfp_dnscommonsrv":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return None

        eventDataHash = self.sf.hashstring(eventData)
        parentEvent = event

        if eventDataHash in self.events:
            return None

        self.events[eventDataHash] = True

        self.sf.debug("Iterating through possible SRV records.")
        # Try resolving common names
        for srv in self.commonsrv:
            if self.checkForStop():
                return None

            name = srv + "." + eventData

            # Skip hosts we've processed already
            if self.sf.hashstring(name) in self.events:
                continue

            try:
                answers = dns.resolver.query(name, 'SRV')
            except BaseException as e:
                answers = []

            for a in answers:
                # Strip off the trailing .
                tgt_clean = a.target.to_text().rstrip(".")
                # Report the host
                if self.getTarget().matches(tgt_clean):
                    evt = SpiderFootEvent("INTERNET_NAME", tgt_clean,
                                          self.__name__, parentEvent)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME", tgt_clean,
                                          self.__name__, parentEvent)
                    self.notifyListeners(evt)

                evt = SpiderFootEvent("DNS_SRV", name,
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)
# End of sfp_dnscommonsrv class
