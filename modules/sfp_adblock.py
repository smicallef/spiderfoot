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
        "blocklist": "https://easylist-downloads.adblockplus.org/easylist.txt"
    }

    optdescs = {
        "blocklist": "AdBlockPlus block list."
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
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["URL_ADBLOCKED_INTERNAL", "URL_ADBLOCKED_EXTERNAL"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.rules is None:
            raw = self.sf.fetchUrl(self.opts['blocklist'], timeout=30)
            if raw['content'] is not None:
                lines = raw['content'].split('\n')
                self.sf.debug("RULE LINES: " + str(len(lines)))
                try:
                    self.rules = adblockparser.AdblockRules(lines)
                except Exception as e:
                    self.errorState = True
                    self.sf.error("Parsing error handling AdBlock list: " + str(e))
            else:
                self.errorState = True
                self.sf.error("Unable to download AdBlockPlus list: " + self.opts['blocklist'])

        if "_EXTERNAL" in eventName:
            pagetype = "_EXTERNAL"
        else:
            pagetype = "_INTERNAL"

        if eventData in self.results:
            self.sf.debug("Already checked this page for AdBlock matching, skipping.")
            return

        self.results[eventData] = True

        try:
            if self.rules and self.rules.should_block(eventData):
                evt = SpiderFootEvent("URL_ADBLOCKED" + pagetype, eventData,
                                      self.__name__, event)
                self.notifyListeners(evt)
        except Exception as e:
            self.sf.error("Parsing error handling AdBlock list: " + str(e))
            self.errorState = True

# End of sfp_adblock class
