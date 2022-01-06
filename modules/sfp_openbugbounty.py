# -------------------------------------------------------------------------------
# Name:         sfp_openbugbounty
# Purpose:      Query the Open Bug Bounty database to see if our target appears.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     04/10/2015
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_openbugbounty(SpiderFootPlugin):

    meta = {
        'name': "Open Bug Bounty",
        'summary': "Check external vulnerability scanning/reporting service openbugbounty.org to see if the target is listed.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.openbugbounty.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.openbugbounty.org/cert/"
            ],
            'favIcon': "https://www.openbugbounty.org/favicon.ico",
            'logo': "https://www.openbugbounty.org/images/design/logo-obbnew.svg",
            'description': "Open Bug Bounty is an open, disintermediated, cost-free, and community-driven bug bounty platform "
            "for coordinated, responsible and ISO 29147 compatible vulnerability disclosure.\n"
            "The role of Open Bug Bounty is limited to independent verification of the "
            "submitted vulnerabilities and proper notification of website owners by all available means. "
            "Once notified, the website owner and the researcher are in direct contact to "
            "remediate the vulnerability and coordinate its disclosure. "
            "At this and at any later stages, we never act as an intermediary between "
            "website owners and security researchers.",
        }
    }
    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["VULNERABILITY_DISCLOSURE"]

    # Query XSSposed.org
    def queryOBB(self, qry):
        ret = list()
        base = "https://www.openbugbounty.org"
        url = "https://www.openbugbounty.org/search/?search=" + qry
        res = self.sf.fetchUrl(url, timeout=30, useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.debug("No content returned from openbugbounty.org")
            return None

        try:
            rx = re.compile(".*<div class=.cell1.><a href=.(.*).>(.*" + qry + ").*?</a></div>.*", re.IGNORECASE)
            for m in rx.findall(str(res['content'])):
                # Report it
                if m[1] == qry or m[1].endswith("." + qry):
                    ret.append("From openbugbounty.org: <SFURL>" + base + m[0] + "</SFURL>")
        except Exception as e:
            self.error("Error processing response from openbugbounty.org: " + str(e))
            return None
        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        data = list()

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        obb = self.queryOBB(eventData)
        if obb:
            data.extend(obb)

        for n in data:
            # Notify other modules of what you've found
            e = SpiderFootEvent("VULNERABILITY_DISCLOSURE", n, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_openbugbounty class
