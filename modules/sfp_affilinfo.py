#-------------------------------------------------------------------------------
# Name:         sfp_affilinfo
# Purpose:      Identify the domain and IP of affiliates (useful for reporting/analysis.)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     8/10/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
import sys
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_affilinfo(SpiderFootPlugin):
    """Affiliate Info:Gather information about confirmed affiliates (IP Addresses, Domains)."""

    # Default options
    opts = { }

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    # Target
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["AFFILIATE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "AFFILIATE_DOMAIN", "AFFILIATE_IPADDR" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        if '://' in eventData:
            fqdn = sf.urlFQDN(eventData)
        else:
            fqdn = eventData

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)
        domain = sf.hostDomain(fqdn, self.opts['_internettlds'])
        sf.debug("Domain for " + fqdn + " is " + domain)

        sf.debug("Affiliate domain: " + domain)
        evt = SpiderFootEvent("AFFILIATE_DOMAIN", domain, self.__name__, event)
        self.notifyListeners(evt)

        # Resolve the IP
        try:
            notif = list()
            addrs = socket.gethostbyname_ex(fqdn)
            for addr in addrs:
                if type(addr) == list:
                    for a in addr:
                        if sf.validIP(a):
                            notif.append(a)
                else:
                    if sf.validIP(addr):            
                        notif.append(addr)
            for a in notif:
                sf.debug("Affiliate IP: " + a)
                evt = SpiderFootEvent("AFFILIATE_IPADDR", a, self.__name__, event)
                self.notifyListeners(evt)

        except BaseException as e:
            sf.debug("Unable to get an IP for " + fqdn + "(" + str(e) + ")")
            return None

# End of sfp_affilinfo class
