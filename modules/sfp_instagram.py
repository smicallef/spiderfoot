#-------------------------------------------------------------------------------
# Name:        sfp_instagram
# Purpose:     Gather information from Instagram profiles.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-07-11
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_instagram(SpiderFootPlugin):
    """Instagram:Footprint,Investigate,Passive:Social Media::Gather information from Instagram profiles."""

    # Default options
    opts = { 
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ 'SOCIAL_MEDIA' ]

    # What events this module produces
    def producedEvents(self):
        return [ 'RAW_RIR_DATA' ]

    # Extract profile JSON from HTML
    def extractJson(self, html):
        m = r'<script type="application/ld\+json">(.+?)</script>'
        json_data = re.findall(m, html, re.MULTILINE | re.DOTALL)

        if not json_data:
            return None

        try:
            data = json.loads(json_data[0])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Parse profile URL
        try:
            network = eventData.split(": ")[0]
            url = eventData.split(": ")[1]
        except BaseException as e:
            self.sf.error("Unable to parse SOCIAL_MEDIA: " +
                          eventData + " (" + str(e) + ")", False)
            return None

        if not network == 'Instagram':
            self.sf.debug("Skipping social network profile, " + url + \
                          ", as not an Instagram profile")
            return None

        # Retrieve profile
        res = self.sf.fetchUrl(url,
                               timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.debug('No response from Instagram.com')
            return None

        # Check if the profile is valid and extract profile data as JSON
        json_data = self.extractJson(res['content'])

        if not json_data:
            self.sf.debug(url + " is not a valid Instagram profile")
            return None

        e = SpiderFootEvent('RAW_RIR_DATA', str(json_data), self.__name__, event)
        self.notifyListeners(e)

# End of sfp_instagram class
