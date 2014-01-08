#-------------------------------------------------------------------------------
# Name:         sfp_blacklist
# Purpose:      SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#               appear in various block lists, indicating potential open-relays,
#               open proxies, malicious servers, vulnerable servers, etc.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/01/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import socket
import random
import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_blacklist(SpiderFootPlugin):
    """Blacklist: Query various blacklist database for open relays, open proxies, vulnerable servers, etc."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    # Target
    baseDomain = None
    results = dict()

    # Whole bunch here:
    # http://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists
    # Check out:
    # http://www.blocklist.de/en/rbldns.html
    checks = {
        "http.dnsbl.sorbs.net": "SORBS - Open HTTP Proxy",
        "socks.dnsbl.sorbs.net": "SORBS - Open SOCKS Proxy",
        "misc.dnsbl.sorbs.net": "SORBS - Open Proxy",
        "smtp.dnsbl.sorbs.net": "SORBS - Open SMTP Relay",
        "spam.dnsbl.sorbs.net": 'SORBS - Spammer',
        "recent.spam.dnsbl.sorbs.net": 'SORBS - Recent Spammer',
        "web.dnsbl.sorbs.net": 'SORBS - Vulnerability exposed to spammers',
        "dnsbl.dronebl.org": {
            "127.0.0.3": "dronebl.org - IRC Drone",
            "127.0.0.5": "dronebl.org - Bottler",
            "127.0.0.6": "dronebl.org - Unknown spambot or drone",
            "127.0.0.7": "dronebl.org - DDOS Drone",
            "127.0.0.8": "dronebl.org - SOCKS Proxy",
            "127.0.0.9": "dronebl.org - HTTP Proxy",
            "127.0.0.10": "dronebl.org - ProxyChain",
            "127.0.0.13": "dronebl.org - Brute force attackers",
            "127.0.0.14": "dronebl.org - Open Wingate Proxy",
            "127.0.0.15": "dronebl.org - Compromised router / gateway",
            "127.0.0.17": "dronebl.org - Automatically determined botnet IPs (experimental)",
            "127.0.0.255": "dronebl.org - Unknown"
        },
        "dnsbl-1.uceprotect.net": 'UCEPROTECT - Level 1 (high likelihood)',
        "dnsbl-2.uceprotect.net": 'UCEPROTECT - Level 2 (some false positives)',
        'zen.spamhaus.net': {
            '127.0.0.2': "Spamhaus (Zen) - Spammer",
            '127.0.0.3': "Spamhaus (Zen) - Spammer",
            '127.0.0.4': "Spamhaus (Zen) - Proxies, Trojans, etc.",
            '127.0.0.5': "Spamhaus (Zen) - Proxies, Trojans, etc.",
            '127.0.0.6': "Spamhaus (Zen) - Proxies, Trojans, etc.",
            '127.0.0.7': "Spamhaus (Zen) - Proxies, Trojans, etc.",
            '127.0.0.10': "Spamhaus (Zen) - Potential Spammer",
            '127.0.0.11': "Spamhaus (Zen) - Potential Spammer"
        }
    }

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = dict()
        self.baseDomain = target

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ 'IP_ADDRESS' ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "BLACKLISTED_IPADDR" ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        return '.'.join(reversed(ipaddr.split('.')))

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.results.has_key(eventData):
            return None

        self.results[eventData] = True

        for domain in self.checks:
            try:
                lookup = self.reverseAddr(eventData) + "." + domain
                sf.debug("Checking Blacklist: " + lookup)
                addrs = socket.gethostbyname_ex(lookup)
                sf.debug("Addresses returned: " + str(addrs))
                for addr in addrs:
                    if  type(addr) == dict:
                        for a in addr:
                            if type(self.checks[domain]) is str:
                                text = self.checks[domain] + " [" + eventData + "]"
                            else:
                                if str(a) not in self.checks[domain].keys():
                                    sf.debug("Return code not found in list: " + str(a))
                                    continue
                                k = str(a)
                                text = self.checks[k] + " [" + eventData + "]"

                            evt = SpiderFootEvent('BLACKLISTED_IPADDR', 
                                text, self.__name__, parentEvent)
                            self.notifyListeners(evt)
                    else:
                        if type(self.checks[domain]) is str:
                            text = self.checks[domain] + " [" + eventData + "]"
                        else:
                            if str(addr) not in self.checks.keys():
                                sf.debug("Return code not found in list: " + str(addr))
                                continue

                            k = str(addr)
                            text = self.checks[k] + " [" + eventData + "]"

                        evt = SpiderFootEvent('BLACKLISTED_IPADDR', 
                            text, self.__name__, parentEvent)
                        self.notifyListeners(evt)
            except BaseException as e:
                sf.debug("Unable to resolve " + eventData + " / " + lookup + ": " + str(e))
 
        return None

# End of sfp_blacklist class
