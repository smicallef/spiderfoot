#-------------------------------------------------------------------------------
# Name:         sfp_honeypot
# Purpose:      SpiderFoot plug-in for looking up whether IPs appear in the
#               projecthoneypot.org database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import socket
import random
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_honeypot(SpiderFootPlugin):
    """Honeypot Checker: Query the projecthoneypot.org database for entries."""

    # Default options
    opts = {
        'apikey': "",
        'searchengine': False,
        'threatscore': 0,
        'timelimit': 30
    }

    # Option descriptions
    optdescs = {
        'apikey': "The API key you obtained from projecthoneypot.org",
        'searchengine': "Include entries considered search engines?",
        'threatscore': "Threat score minimum, 0 being everything and 255 being only the most serious.",
        'timelimit': "Maximum days old an entry can be. 255 is the maximum, 0 means you'll get nothing."
    }

    results = dict()

    # Status codes according to:
    # http://www.projecthoneypot.org/httpbl_api.php
    statuses = {
        "0": "Search Engine",
        "1": "Suspicious",
        "2": "Harvester",
        "3": "Suspicious & Harvester",
        "4": "Comment Spammer",
        "5": "Suspicious & Comment Spammer",
        "6": "Harvester & Comment Spammer",
        "7": "Suspicious & Harvester & Comment Spammer",
        "8": "Unknown (8)",
        "9": "Unknown (9)",
        "10": "Unknown (10)"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ 'IP_ADDRESS', 'AFFILIATE_IPADDR' ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "BLACKLISTED_IPADDR", "BLACKLISTED_AFFILIATE_IPADDR" ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        return '.'.join(reversed(ipaddr.split('.')))

    # Returns text about the IP status returned from DNS
    def reportIP(self, addr):
        bits = addr.split(".")
        if int(bits[1]) > self.opts['timelimit']:
            return None

        if int(bits[2]) < self.opts['threatscore']:
            return None

        if int(bits[3]) == 0 and self.opts['searchengine']:
            return None

        text = "Honeypotproject: " + self.statuses[bits[3]] + \
            "\nLast Activity: " + bits[1] + " days ago" + \
            "\nThreat Level: " + bits[2]
        return text

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['apikey'] == "":
            self.sf.error("You enabled sfp_honeypot but did not set an API key!", False)
            return None

        if self.results.has_key(eventData):
            return None
        self.results[eventData] = True

        try:
            lookup = self.opts['apikey'] + "." + \
                self.reverseAddr(eventData) + ".dnsbl.httpbl.org"

            self.sf.debug("Checking Honeypot: " + lookup)
            addrs = socket.gethostbyname_ex(lookup)
            self.sf.debug("Addresses returned: " + str(addrs))

            text = None
            for addr in addrs:
                if type(addr) == list:
                    for a in addr:
                        text = self.reportIP(a)
                        if text == None:
                            continue
                        else:
                            break
                else:
                    text = self.reportIP(addr)
                    if text == None:
                        continue
                    else:
                        break

            if text != None:
                if eventName == "AFFILIATE_IPADDR":
                    evt = SpiderFootEvent('BLACKLISTED_AFFILIATE_IPADDR',
                        text, self.__name__, parentEvent)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent('BLACKLISTED_IPADDR', 
                        text, self.__name__, parentEvent)
                    self.notifyListeners(evt)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + eventData + " / " + lookup + ": " + str(e))
 
# End of sfp_honeypot class
