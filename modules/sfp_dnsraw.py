# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsraw
# Purpose:      SpiderFoot plug-in for collecting raw DNS records.
#               Also extracts hostnames from SPF records.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/07/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
import re
import dns
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnsraw(SpiderFootPlugin):
    """DNS Raw Records:Footprint,Investigate,Passive:DNS::Retrieves raw DNS records such as MX, TXT and others."""

    # Default options
    opts = {
        'verify': True,
    }

    # Option descriptions
    optdescs = {
        'verify': "Verify SPF hostnames resolve."
    }

    events = None
    checked = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = self.tempStorage()
        self.checked = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', 'DOMAIN_NAME', 'DOMAIN_NAME_PARENT']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["PROVIDER_MAIL", "PROVIDER_DNS", "RAW_DNS_RECORDS",
                "DNS_TEXT", "DNS_SPF", "AFFILIATE_INTERNET_NAME",
                'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED',
                'AFFILIATE_DOMAIN', 'AFFILIATE_DOMAIN_UNRESOLVED']

    # Resolve a host
    def resolveHost(self, host):
        try:
            # IDNA-encode the hostname in case it contains unicode
            if type(host) != unicode:
                host = unicode(host, "utf-8", errors='replace').encode("idna")
            else:
                host = host.encode("idna")

            addrs = socket.gethostbyname_ex(host)
            if not addrs:
                return False

            return True
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventDataHash in self.events:
            self.sf.debug("Skipping duplicate event for " + eventData)
            return None

        self.events[eventDataHash] = True

        self.sf.debug("Gathering DNS records for " + eventData)
        # Process the raw data alone
        recdata = dict()
        recs = {
            'MX': ['\S+\s+(?:\d+)?\s+IN\s+MX\s+\d+\s+(\S+)\.', 'PROVIDER_MAIL'],
            'NS': ['\S+\s+(?:\d+)?\s+IN\s+NS\s+(\S+)\.', 'PROVIDER_DNS'],
            'TXT': ['\S+\s+TXT\s+\"(.[^\"]*)"', 'DNS_TEXT']
        }

        for rec in recs.keys():
            if self.checkForStop():
                return None

            try:
                req = dns.message.make_query(eventData, dns.rdatatype.from_text(rec))

                if self.opts.get('_dnsserver', None):
                    n = self.opts['_dnsserver']
                else:
                    ns = dns.resolver.get_default_resolver()
                    n = ns.nameservers[0]

                res = dns.query.udp(req, n, timeout=30)
                for x in res.answer:
                    if str(x) in self.checked:
                        continue
                    self.checked[str(x)] = True
                    for rx in recs.keys():
                        self.sf.debug("Checking " + str(x) + " + against " + recs[rx][0])
                        pat = re.compile(recs[rx][0], re.IGNORECASE | re.DOTALL)
                        grps = re.findall(pat, str(x))

                        if len(grps) == 0:
                            continue

                        for m in grps:
                            self.sf.debug("Matched: " + m)
                            strdata = unicode(m, 'utf-8', errors='replace')
                            evt = SpiderFootEvent(recs[rx][1], strdata,
                                                      self.__name__, parentEvent)
                            self.notifyListeners(evt)
                            if rec != "TXT" and not strdata.endswith(eventData):
                                evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME",
                                                      strdata, self.__name__, parentEvent)
                                self.notifyListeners(evt)

                            if rec == "TXT" and "v=spf" in strdata:
                                evt = SpiderFootEvent("DNS_SPF", strdata,
                                                      self.__name__, parentEvent)
                                self.notifyListeners(evt)

                                matches = re.findall(r'include:(.+?) ', strdata, re.IGNORECASE | re.DOTALL)
                                if matches:
                                    for domain in matches:
                                        if self.getTarget().matches(domain, includeChildren=True):
                                            evt_type = 'INTERNET_NAME'
                                        else:
                                            evt_type = 'AFFILIATE_DOMAIN'

                                        if self.opts['verify'] and not self.resolveHost(domain):
                                            self.sf.debug("Host " + domain + " could not be resolved")
                                            evt_type += '_UNRESOLVED'

                                        evt = SpiderFootEvent(evt_type, domain, self.__name__, parentEvent)
                                        self.notifyListeners(evt)

                    strdata = unicode(str(x), 'utf-8', errors='replace')
                    evt = SpiderFootEvent("RAW_DNS_RECORDS", strdata,
                                          self.__name__, parentEvent)
                    self.notifyListeners(evt)
            except BaseException as e:
                self.sf.error("Failed to obtain DNS response for " + eventData +
                              "(" + rec + "): " + str(e), False)

# End of sfp_dnsraw class
