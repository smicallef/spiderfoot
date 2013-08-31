#-------------------------------------------------------------------------------
# Name:         sfp_searchtld
# Purpose:      SpiderFoot plug-in for identifying the existence of this target
#               on other TLDs.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     31/08/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import dns.resolver
import socket
import sys
import re
import time
import random
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_searchtld(SpiderFootPlugin):
    """Search all Internet TLDs for domains with the same name as the target."""

    # Default options
    opts = {
        'activeonly':   True, # Only report domains that have content (try to fetch the page)
        'checkcommon':  True, # For every TLD, try the common domains like com, net, etc. too
        'commontlds':   ['com', 'info', 'net', 'org', 'biz', 'co', 'edu', 'gov', 'mil' ],
        'tldlist':      "http://data.iana.org/TLD/tlds-alpha-by-domain.txt",
        'skipwildcards':    True
    }

    # Option descriptions
    optdescs = {
        'activeonly':   "Only report domains that have content (try to fetch the page)?",
        'checkcommon':  "For every TLD, also prepend each common sub-TLD (com, net, ...)",
        "commontlds":   "Common sub-TLDs to try when iterating through all Internet TLDs.",
        "tldlist":      "The list of all Internet TLDs.",
        "skipwildcards":    "Skip TLDs and sub-TLDs that have wildcard DNS."
    }

    # Internal results tracking
    results = list()

    # Target
    baseDomain = None

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return None

    # Store the result internally and notify listening modules
    def storeResult(self, source, result):
        if result == self.baseDomain:
            return

        sf.info("Found a TLD with the target's name: " + result)
        self.results.append(result)

        # Inform listening modules
        if self.opts['activeonly']:
            if self.checkForStop():
                return None

            pageContent = sf.fetchUrl('http://' + result)
            if pageContent['content'] != None:
                evt = SpiderFootEvent("SIMILARDOMAIN", result, self.__name__)
                self.notifyListeners(evt)
        else:
            evt = SpiderFootEvent("SIMILARDOMAIN", result, self.__name__)
            self.notifyListeners(evt)


    # Search for similar sounding domains
    def start(self):
        keyword = sf.domainKeyword(self.baseDomain)
        sf.debug("Keyword extracted from " + self.baseDomain + ": " + keyword)

        # No longer seems to work.
        #if "whois" in self.opts['source'] or "ALL" in self.opts['source']:
        #    self.scrapeWhois(keyword)

        # Look through all TLDs for the existence of this target keyword
        tldlistContent = sf.fetchUrl(self.opts['tldlist'])
        if tldlistContent['content'] == None:
            sf.error("Unable to obtain TLD list from " + self.opts['tldlist'], False)
        else:
            for tld in tldlistContent['content'].lower().splitlines():
                if tld.startswith("#") or sf.checkDnsWildcard(tld):
                    continue

                tryDomain = keyword + "." + tld
                sf.debug("Trying " + tryDomain)

                if self.checkForStop():
                    return None

                # Try to resolve <target>.<TLD>
                try:
                    addrs = socket.gethostbyname_ex(tryDomain)
                    self.storeResult(None, tryDomain)
                except BaseException as e:
                    sf.debug("Unable to resolve " + tryDomain + "(" + str(e) + ")")

                # Try to resolve <target>.<subTLD>.<TLD>
                if self.opts['checkcommon']:
                    for subtld in self.opts['commontlds']:
                        if sf.checkDnsWildcard(subtld + "." + tld):
                            continue

                        subDomain = keyword + "." + subtld + "." + tld 

                        if self.checkForStop():
                            return None

                        try:
                            addrs = socket.gethostbyname_ex(subDomain)
                            self.storeResult(None, subDomain)
                        except BaseException as e:
                            sf.debug("Unable to resolve " + subDomain + "(" + str(e) + ")")

        return None

# End of sfp_searchtld class
