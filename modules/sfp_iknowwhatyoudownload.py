#-------------------------------------------------------------------------------
# Name:         sfp_iknowwhatyoudownload
# Purpose:      Query iknowwhatyoudownload.com for IP addresses using BitTorrent.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/09/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_iknowwhatyoudownload(SpiderFootPlugin):
    """Iknowwhatyoudownload.com:Footprint,Investigate,Passive:Secondary Networks:apikey:Check iknowwhatyoudownload.com for IP addresses that have been using BitTorrent."""


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

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        ret = ["IP_ADDRESS"]

        return ret

    # What events this module produces
    def producedEvents(self):
        ret = ["MALICIOUS_IPADDR"]

        return ret

    def query(self, qry):
        ret = None
        retdata = None

        base = "https://api.antitor.com/history/peer/?ip="
        url = base + qry + "&days=" + str(self.opts['daysback'])
        url += "&key=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
            useragent="SpiderFoot")

        if res['code'] in ["403", "500"]:
            self.sf.info("Unable to fetch data from iknowwhatyoudownload.com right now.")
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from iknowwhatyoudownload.com: " + str(e), False)
            return None

        if 'error' in ret:
            if ret['error'] == "INVALID_DAYS":
                self.errorState = True
                self.sf.error("The number of days you have configured is not accepted. If you have the demo key, try 30 days or less.", False)
                return None
        
        if 'contents' in ret:
            if len(ret['contents']) > 0:
                retdata = "<SFURL>https://iknowwhatyoudownload.com/en/peer/?ip=" + qry + "</SFURL>\n"
                for d in ret['contents']:
                    retdata += d['torrent']['name'] + \
                               " (" + d.get("endDate", "Date unknown") + ")\n"
            else:
                return None
        else:
            return None    

        return retdata

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.errorState:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_iknowwhatyoudownload but did not set an API key!", False)
            self.errorState = True
            return None

       # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        data = self.query(eventData)
        if data == None:
            return None
        else:
            e = SpiderFootEvent("MALICIOUS_IPADDR", data, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_iknowwhatyoudownload class
