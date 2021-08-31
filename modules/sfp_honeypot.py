# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_honeypot
# Purpose:      SpiderFoot plug-in for looking up whether IPs appear in the
#               projecthoneypot.org database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_honeypot(SpiderFootPlugin):

    meta = {
        'name': "Honeypot Checker",
        'summary': "Query the projecthoneypot.org database for entries.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.projecthoneypot.org/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://www.projecthoneypot.org/httpbl_api.php",
                "https://www.projecthoneypot.org/services_overview.php",
                "https://www.projecthoneypot.org/faq.php"
            ],
            'apiKeyInstructions': [
                "Visit https://www.projecthoneypot.org",
                "Sign up for a free account",
                "Navigate to https://www.projecthoneypot.org/httpbl_configure.php'",
                "Request for an API key",
                "The API key is listed under 'Your http:BL Access Key'"
            ],
            'favIcon': "https://www.projecthoneypot.org/favicon.ico",
            'logo': "https://www.projecthoneypot.org/images/php_logo.gif",
            'description': "Project Honey Pot is the first and only distributed system for identifying spammers "
            "and the spambots they use to scrape addresses from your website. "
            "Using the Project Honey Pot system you can install addresses "
            "that are custom-tagged to the time and IP address of a visitor to your site. "
            "If one of these addresses begins receiving email we not only can tell that the messages are spam, "
            "but also the exact moment when the address was harvested and the IP address that gathered it.",
        }
    }

    # Default options
    opts = {
        'api_key': "",
        'searchengine': False,
        'threatscore': 0,
        'timelimit': 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        'api_key': "Projecthoneypot.org API key.",
        'searchengine': "Include entries considered search engines?",
        'threatscore': "Threat score minimum, 0 being everything and 255 being only the most serious.",
        'timelimit': "Maximum days old an entry can be. 255 is the maximum, 0 means you'll get nothing.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False

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
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'AFFILIATE_IPADDR', 'NETBLOCK_OWNER',
                'NETBLOCK_MEMBER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["BLACKLISTED_IPADDR", "BLACKLISTED_AFFILIATE_IPADDR",
                "BLACKLISTED_SUBNET", "BLACKLISTED_NETBLOCK"]

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

        return "Honeypotproject ({0}): " + self.statuses[bits[3]] + \
               "\nLast Activity: " + bits[1] + " days ago" + \
               "\nThreat Level: " + bits[2]

    def queryAddr(self, qaddr, parentEvent):
        eventName = parentEvent.eventType

        try:
            lookup = f"{self.opts['api_key']}.{self.reverseAddr(qaddr)}.dnsbl.httpbl.org"

            self.sf.debug(f"Checking Honeypot: {lookup}")
            addrs = self.sf.resolveHost(lookup)
            if not addrs:
                return

            self.sf.debug(f"Addresses returned: {addrs}")

            text = None
            for addr in addrs:
                text = self.reportIP(addr)
                if text is not None:
                    break

            if text is not None:
                if eventName == "AFFILIATE_IPADDR":
                    e = "BLACKLISTED_AFFILIATE_IPADDR"
                if eventName == "IP_ADDRESS":
                    e = "BLACKLISTED_IPADDR"
                if eventName == "NETBLOCK_OWNER":
                    e = "BLACKLISTED_NETBLOCK"
                if eventName == "NETBLOCK_MEMBER":
                    e = "BLACKLISTED_SUBNET"

                evt = SpiderFootEvent(e, text.format(qaddr), self.__name__, parentEvent)
                self.notifyListeners(evt)
        except Exception as e:
            self.sf.debug("Unable to resolve " + qaddr + " / " + lookup + ": " + str(e))

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_honeypot but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return
        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxnetblock']))
                    return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxsubnet']))
                    return

        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                if self.checkForStop():
                    return
                self.queryAddr(str(addr), parentEvent)
        else:
            self.queryAddr(eventData, parentEvent)

# End of sfp_honeypot class
