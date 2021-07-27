# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_botscout
# Purpose:      SpiderFoot plug-in to search botsout.com using their API, for
#               potential malicious IPs and e-mail addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/07/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_botscout(SpiderFootPlugin):

    meta = {
        'name': "BotScout",
        'summary': "Searches botscout.com's database of spam-bot IPs and e-mail addresses.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://botscout.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "http://botscout.com/api.htm",
                "http://botscout.com/api_queries.htm",
                "http://botscout.com/getkey.htm",
                "http://botscout.com/corp_users.htm"
            ],
            'apiKeyInstructions': [
                "Visit http://botscout.com/getkey.htm",
                "Register a free account",
                "The API key will be emailed to your account"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=http://botscout.com/",
            'logo': "http://botscout.com/image/bslogo.gif",
            'description': "BotScout helps prevent automated web scripts, known as \"bots\", "
            "from registering on forums, polluting databases, spreading spam, "
            "and abusing forms on web sites. We do this by tracking the names, IPs, "
            "and email addresses that bots use and logging them as unique signatures for future reference. "
            "We also provide a simple yet powerful API that you can use to test forms "
            "when they're submitted on your site.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "Botscout.com API key. Without this you will be limited to 50 look-ups per day."
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'EMAILADDR']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_botscout but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData} as already searched.")
            return

        self.results[eventData] = True

        if self.opts['api_key']:
            url = "http://botscout.com/test/?key=" + self.opts['api_key'] + "&all="
        else:
            url = "http://botscout.com/test/?all="

        res = self.sf.fetchUrl(url + eventData,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])
        if res['content'] is None or "|" not in res['content']:
            self.sf.error("Error encountered processing " + eventData)
            return

        if res['content'].startswith("Y|"):
            self.sf.info("Found Botscout entry for " + eventData + ": " + res['content'])
            if eventName == "IP_ADDRESS":
                t = "MALICIOUS_IPADDR"
            else:
                t = "MALICIOUS_EMAILADDR"

            evt = SpiderFootEvent(t, "Botscout [" + eventData + "]", self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_botscout class
