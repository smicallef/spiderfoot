# -------------------------------------------------------------------------------
# Name:         sfp_iknowwhatyoudownload
# Purpose:      Query iknowwhatyoudownload.com for IP addresses using BitTorrent.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/09/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_iknowwhatyoudownload(SpiderFootPlugin):

    meta = {
        'name': "Iknowwhatyoudownload.com",
        'summary': "Check iknowwhatyoudownload.com for IP addresses that have been using BitTorrent.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://iknowwhatyoudownload.com/en/peer/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://iknowwhatyoudownload.com/en/api/",
                "https://iknowwhatyoudownload.com/en/link/",
                "https://iknowwhatyoudownload.com/en/peer/"
            ],
            'apiKeyInstructions': [
                "Visit https://iknowwhatyoudownload.com/en/api/",
                "Request Demo Key with email id",
                "The API key will be sent to your email"
            ],
            'favIcon': "https://iknowwhatyoudownload.com/assets/img/utorrent2.png",
            'logo': "https://iknowwhatyoudownload.com/assets/img/logo.png",
            'description': "Our system collects torrent files in two ways: parsing torrent sites, and listening DHT network. "
            "We have more than 1.500.000 torrents which where classified and which are using now "
            "for collecting peer sharing facts (up to 200.000.000 daily).",
        }
    }

    # Default options
    opts = {
        "daysback": 30,
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "daysback": "How far back (in days) to look for activity.",
        "api_key": "Iknowwhatyoudownload.com API key."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR"]

    def query(self, qry):
        ret = None
        retdata = None

        url = "https://api.antitor.com/history/peer/?ip="
        url += qry + "&days=" + str(self.opts['daysback'])
        url += "&key=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot")

        if res['code'] in ["403", "500"]:
            self.sf.info("Unable to fetch data from iknowwhatyoudownload.com right now.")
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from iknowwhatyoudownload.com: {e}")
            return None

        if 'error' in ret:
            if ret['error'] == "INVALID_DAYS":
                self.errorState = True
                self.sf.error("The number of days you have configured is not accepted. If you have the demo key, try 30 days or less.")
                return None

        if 'contents' not in ret:
            return None

        if not len(ret['contents']):
            return None

        retdata = f"<SFURL>https://iknowwhatyoudownload.com/en/peer/?ip={qry}</SFURL>\n"
        for d in ret['contents']:
            retdata += d['torrent']['name'] + " (" + d.get("endDate", "Date unknown") + ")\n"

        return retdata

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_iknowwhatyoudownload but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)

        if not data:
            return

        e = SpiderFootEvent("MALICIOUS_IPADDR", data, self.__name__, event)
        self.notifyListeners(e)

# End of sfp_iknowwhatyoudownload class
