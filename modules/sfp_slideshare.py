# -------------------------------------------------------------------------------
# Name:         sfp_slideshare
# Purpose:      Query SlideShare for name and location information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-15
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_slideshare(SpiderFootPlugin):

    meta = {
        'name': "SlideShare",
        'summary': "Gather name and location from SlideShare profiles.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://www.slideshare.net",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.slideshare.net/developers/documentation",
                "https://www.slideshare.net/developers",
                "https://www.slideshare.net/developers/resources",
                "https://www.slideshare.net/developers/oembed"
            ],
            'favIcon': "https://public.slidesharecdn.com/favicon.ico?d8e2a4ed15",
            'logo': "https://public.slidesharecdn.com/images/logo/linkedin-ss/SS_Logo_White_Large.png?6d1f7a78a6",
            'description': "LinkedIn SlideShare is an American hosting service for professional content including "
            "presentations, infographics, documents, and videos. "
            "Users can upload files privately or publicly in PowerPoint, Word, PDF, or OpenDocument format.",
        }
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["SOCIAL_MEDIA"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO"]

    # Extract meta property contents from HTML
    def extractMeta(self, meta_property, html):
        return re.findall(r'<meta property="' + meta_property + r'"\s+content="(.+)" />', html)

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Retrieve profile
        try:
            network = eventData.split(": ")[0]
            url = eventData.split(": ")[1].replace("<SFURL>", "").replace("</SFURL>", "")
        except Exception as e:
            self.debug(f"Unable to parse SOCIAL_MEDIA: {eventData} ({e})")
            return

        if network != "SlideShare":
            self.debug(f"Skipping social network profile, {url}, as not a SlideShare profile")
            return

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            return

        # Check if the profile is valid and extract name
        human_name = self.extractMeta('slideshare:name', res['content'])

        if not human_name:
            self.debug(f"{url} is not a valid SlideShare profile")
            return

        e = SpiderFootEvent("RAW_RIR_DATA", f"Possible full name: {human_name[0]}", self.__name__, event)
        self.notifyListeners(e)

        # Retrieve location (country)
        location = self.extractMeta('slideshare:location', res['content'])

        if not location:
            return

        if len(location[0]) < 3 or len(location[0]) > 100:
            self.debug("Skipping likely invalid location.")
            return

        e = SpiderFootEvent("GEOINFO", location[0], self.__name__, event)
        self.notifyListeners(e)

# End of sfp_slideshare class
