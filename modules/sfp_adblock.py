# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_adblock
# Purpose:      SpiderFoot plug-in to test if external/internally linked pages
#               would be blocked by AdBlock Plus.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/09/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import adblockparser

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_adblock(SpiderFootPlugin):

    meta = {
        'name': "AdBlock Check",
        'summary': "Check if linked pages would be blocked by AdBlock Plus.",
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://adblockplus.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://help.eyeo.com/en/adblockplus/",
                "https://adblockplus.org/en/download",
                "https://adblockplus.org/en/filters#options",
                "https://chrome.google.com/webstore/detail/adblock-plus-free-ad-bloc/cfhdojbkjhnklbpkdaibdccddilifddb"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://adblockplus.org/en/",
            'logo': "https://adblockplus.org/img/navbar-logo.svg",
            'description': "Adblock Plus is a free extension that allows you to customize your web experience."
            "You can block annoying ads, disable tracking and lots more."
            "It’s available for all major desktop browsers and for your mobile devices.\n"
            "Block ads that interrupt your browsing experience."
            "Say goodbye to video ads, pop-ups, flashing banners and more."
            "Blocking these annoyances means pages load faster.\n"
            "With Adblock Plus avoiding tracking and malware is easy."
            "Blocking intrusive ads reduces the risk of \"malvertising\" infections."
            "Blocking tracking stops companies following your online activity."
        }
    }

    # Default options
    opts = {
        "blocklist": "https://easylist-downloads.adblockplus.org/easylist.txt",
        'cacheperiod': 24,
    }

    optdescs = {
        "blocklist": "AdBlockPlus block list.",
        'cacheperiod': "Hours to cache list data before re-fetching.",
    }

    results = None
    rules = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.rules = None
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL", "PROVIDER_JAVASCRIPT"]

    # What events this module produces
    def producedEvents(self):
        return ["URL_ADBLOCKED_INTERNAL", "URL_ADBLOCKED_EXTERNAL"]

    def retrieveBlocklist(self, blocklist_url):
        if not blocklist_url:
            return None

        blocklist = self.sf.cacheGet(f"adblock_{blocklist_url}", 24)

        if blocklist is not None:
            return self.setBlocklistRules(blocklist)

        res = self.sf.fetchUrl(blocklist_url, timeout=30)

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} for {blocklist_url}")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error(f"Unable to download AdBlock Plus blocklist: {blocklist_url}")
            self.errorState = True
            return None

        self.sf.cachePut(f"adblock_{blocklist_url}", res['content'])

        return self.setBlocklistRules(res['content'])

    def setBlocklistRules(self, blocklist):
        """Parse AdBlock Plus blocklist and set blocklist rules

        Args:
            blocklist (str): plaintext AdBlock Plus blocklist
        """
        if not blocklist:
            return

        lines = blocklist.split('\n')
        self.debug(f"Retrieved {len(lines)} AdBlock blocklist rules")
        try:
            self.rules = adblockparser.AdblockRules(lines)
        except adblockparser.AdblockParsingError as e:
            self.errorState = True
            self.error(f"Parsing error handling AdBlock list: {e}")

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug("Already checked this URL for AdBlock matching, skipping.")
            return

        self.results[eventData] = True

        if self.errorState:
            return

        if not self.opts["blocklist"]:
            self.error(
                f"You enabled {self.__class__.__name__} but did not set a blocklist URL!"
            )
            self.errorState = True
            return

        if not self.rules:
            self.retrieveBlocklist(self.opts['blocklist'])

        if not self.rules:
            self.error("No AdBlock Plus rules loaded")
            self.errorState = True
            return

        try:
            if eventName == 'PROVIDER_JAVASCRIPT':
                if self.rules and self.rules.should_block(eventData, {'third-party': True, 'script': True}):
                    evt = SpiderFootEvent("URL_ADBLOCKED_EXTERNAL", eventData, self.__name__, event)
                    self.notifyListeners(evt)

            if eventName == 'LINKED_URL_EXTERNAL':
                if self.rules and self.rules.should_block(eventData, {'third-party': True}):
                    evt = SpiderFootEvent("URL_ADBLOCKED_EXTERNAL", eventData, self.__name__, event)
                    self.notifyListeners(evt)

            if eventName == 'LINKED_URL_INTERNAL':
                if self.rules and self.rules.should_block(eventData):
                    evt = SpiderFootEvent("URL_ADBLOCKED_INTERNAL", eventData, self.__name__, event)
                    self.notifyListeners(evt)

        except ValueError as e:
            self.error(f"Parsing error handling AdBlock list: {e}")
            self.errorState = True

# End of sfp_adblock class
