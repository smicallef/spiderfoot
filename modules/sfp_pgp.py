# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pgp
# Purpose:      SpiderFoot plug-in for looking up received e-mails in PGP
#               key servers as well as finding e-mail addresses belonging to
#               your target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/02/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_pgp(SpiderFootPlugin):
    """PGP Key Look-up:Footprint,Investigate,Passive:Public Registries::Look up e-mail addresses in PGP public key servers."""


    results = list()

    # Default options
    opts = {
        # options specific to this module
        'keyserver1_search': "http://pgp.mit.edu/pks/lookup?op=index&search=",
        'keyserver1_fetch': "http://pgp.mit.edu/pks/lookup?op=get&search=",
        'keyserver2_search': "https://hkps.pool.sks-keyservers.net/pks/lookup?op=vindex&search=",
        'keyserver2_fetch': "https://hkps.pool.sks-keyservers.net/pks/lookup?op=get&search="
    }

    # Option descriptions
    optdescs = {
        'keyserver1_search': "PGP public key server URL to find e-mail addresses on a domain. Domain will get appended.",
        'keyserver1_fetch': "PGP public key server URL to find the public key for an e-mail address. Email address will get appended.",
        'keyserver2_search': "Backup PGP public key server URL to find e-mail addresses on a domain. Domain will get appended.",
        'keyserver2_fetch': "Backup PGP public key server URL to find the public key for an e-mail address. Email address will get appended."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "PGP Key Servers"
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR", "PGP_KEY"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Get e-mail addresses on this domain
        if eventName == "DOMAIN_NAME":
            res = self.sf.fetchUrl(self.opts['keyserver1_search'] + eventData,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                res = self.sf.fetchUrl(self.opts['keyserver2_search'] + eventData,
                                       timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

            if res['content'] is not None:
                pat = re.compile("([a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)")
                matches = re.findall(pat, res['content'])
                for match in matches:
                    self.sf.debug("Found possible email: " + match)
                    if len(match) < 4:
                        self.sf.debug("Likely invalid address.")
                        continue

                    mailDom = match.lower().split('@')[1]
                    if not self.getTarget().matches(mailDom):
                        self.sf.debug("Ignoring e-mail address on an external domain: " + match)
                        continue

                    self.sf.info("Found e-mail address: " + match)
                    evt = SpiderFootEvent("EMAILADDR", match, self.__name__, event)
                    self.notifyListeners(evt)

        if eventName == "EMAILADDR":
            res = self.sf.fetchUrl(self.opts['keyserver1_fetch'] + eventData,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
               res = self.sf.fetchUrl(self.opts['keyserver2_fetch'] + eventData,
                                      timeout=self.opts['_fetchtimeout'],
                                      useragent=self.opts['_useragent'])

            if res['content'] is not None:
                pat = re.compile("(-----BEGIN.*END.*BLOCK-----)", re.MULTILINE | re.DOTALL)
                matches = re.findall(pat, res['content'])
                for match in matches:
                    self.sf.debug("Found public key: " + match)
                    if len(match) < 300:
                        self.sf.debug("Likely invalid public key.")
                        continue

                    evt = SpiderFootEvent("PGP_KEY", match, self.__name__, event)
                    self.notifyListeners(evt)

        return None

# End of sfp_pgp class
