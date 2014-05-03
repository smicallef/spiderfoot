#-------------------------------------------------------------------------------
# Name:         sfp_virustotal
# Purpose:      Query VirusTotal for identified IP addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_virustotal(SpiderFootPlugin):
    """VirusTotal:Obtain information from VirusTotal about identified IP addresses."""

    # Default options
    opts = { 
        "apikey":   "",
        "publicapi":    True,
        "checkcohosts": True,
        "checkaffiliates":  True
    }

    # Option descriptions
    optdescs = {
        "apikey":   "Your VirusTotal API Key.",
        "publicapi":    "Are you using a public key? If so SpiderFoot will pause for 15 seconds after each query to avoid VirusTotal dropping requests.",
        "checkcohosts": "Check co-hosted sites?",
        "checkaffiliates": "Check affiliates?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "DOMAIN_NAME",
            "AFFILIATE_DOMAIN", "CO_HOSTED_SITE"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_SUBDOMAIN",
            "MALICIOUS_COHOST", "MALICIOUS_AFFILIATE",
            "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['apikey'] == "":
            sf.error("You enabled sfp_virustotal but did not set an API key!", False)
            return None

       # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return None

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return None

        if eventName in [ "AFFILIATE_DOMAIN", "CO_HOSTED_SITE" ]:
            url = "https://www.virustotal.com/vtapi/v2/domain/report?domain="
        else:
            url = "https://www.virustotal.com/vtapi/v2/ip-address/report?ip="

        res = sf.fetchUrl(url + eventData + "&apikey=" + self.opts['apikey'],
            timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot")

        # Public API is limited to 4 queries per minute
        if self.opts['publicapi']:
            time.sleep(15)

        if res['content'] == None:
            sf.info("No VirusTotal info found for " + eventData)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            sf.error("Error processing JSON response from VirusTotal.", False)
            return None

        if info.has_key('detected_urls'):
            sf.info("Found VirusTotal URL data for " + eventData)
            if eventName == "IP_ADDRESS":
                evt = "MALICIOUS_IPADDR"
                infotype = "ip-address"

            if eventName == "AFFILIATE_IPADDR":
                evt = "MALICIOUS_AFFILIATE_IPADDR"
                infotype = "ip-address"

            if eventName == "DOMAIN_NAME":
                evt = "MALICIOUS_DOMAIN_NAME"
                infotype = "domain"

            if eventName == "AFFILIATE_DOMAIN":
                evt = "MALICIOUS_AFFILIATE"
                infotype = "domain"

            if eventName == "CO_HOSTED_SITE":
                evt = "MALICIOUS_COHOST"
                infotype = "domain"

            infourl = "<SFURL>https://www.virustotal.com/en/" + infotype + "/" + \
                eventData + "/information/</SFURL>"

            # Notify other modules of what you've found
            e = SpiderFootEvent(evt, "VirusTotal [" + eventData + "]\n" + \
                infourl, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_virustotal class
