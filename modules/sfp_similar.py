# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_similar
# Purpose:      SpiderFoot plug-in for identifying domains that look similar
#               to the one being queried.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/11/2016
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

nearchars = {
    'a': ['4', 's'],
    'b': ['v', 'n'],
    'c': ['x', 'v'],
    'd': ['s', 'f'],
    'e': ['w', 'r'],
    'f': ['d', 'g'],
    'g': ['f', 'h'],
    'h': ['g', 'j', 'n'],
    'i': ['o', 'u', '1'],
    'j': ['k', 'h', 'i'],
    'k': ['l', 'j'],
    'l': ['i', '1', 'k'],
    'm': ['n'],
    'n': ['m'],
    'o': ['p', 'i', '0'],
    'p': ['o', 'q'],
    'r': ['t', 'e'],
    's': ['a', 'd', '5'],
    't': ['7', 'y', 'z', 'r'],
    'u': ['v', 'i', 'y', 'z'],
    'v': ['u', 'c', 'b'],
    'w': ['v', 'vv', 'q', 'e'],
    'x': ['z', 'y', 'c'],
    'y': ['z', 'x'],
    'z': ['y', 'x'],
    '0': ['o'],
    '1': ['l'],
    '2': ['5'],
    '3': ['e'],
    '4': ['a'],
    '5': ['s'],
    '6': ['b'],
    '7': ['t'],
    '8': ['b'],
    '9': []
}

pairs = {
    'oo': ['00'],
    'll': ['l1l', 'l1l', '111', '11'],
    '11': ['ll', 'lll', 'l1l', '1l1']
}


class sfp_similar(SpiderFootPlugin):

    meta = {
        'name': "Similar Domain Finder",
        'summary': "Search various sources to identify similar looking domain names, for instance squatted domains.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    # Internal results tracking
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SIMILARDOMAIN"]

    # Search for similar sounding domains
    def handleEvent(self, event):
        eventData = event.data

        dom = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        if not dom:
            return

        tld = "." + eventData.split(dom + ".")[-1]
        self.debug(f"Keyword extracted from {eventData}: {dom}")

        if dom in self.results:
            return

        self.results[dom] = True

        domlist = list()

        # Search for typos
        pos = 0
        for c in dom:
            if c not in nearchars:
                continue
            if len(nearchars[c]) == 0:
                continue
            npos = pos + 1
            for xc in nearchars[c]:
                newdom = dom[0:pos] + xc + dom[npos:len(dom)]
                domlist.append(newdom)

            pos += 1

        # Search for common double-letter re
        for p in pairs:
            if p in dom:
                for r in pairs[p]:
                    domlist.append(dom.replace(p, r))

        # Search for prefixed and suffixed domains
        for c in nearchars:
            domlist.append(dom + c)
            domlist.append(c + dom)

        # Search for double character domains
        pos = 0
        for c in dom:
            domlist.append(dom[0:pos] + c + c + dom[(pos + 1):len(dom)])
            pos += 1

        for d in domlist:
            try:
                for domain in [f"{d}{tld}", f"www.{d}{tld}"]:
                    if self.sf.resolveHost(domain) or self.sf.resolveHost6(domain):
                        self.debug(f"Resolved {domain}")
                        evt = SpiderFootEvent("SIMILARDOMAIN", f"{d}{tld}", self.__name__, event)
                        self.notifyListeners(evt)
                        break
            except Exception:
                continue

# End of sfp_similar class
