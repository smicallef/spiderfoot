# -------------------------------------------------------------------------------
# Name:        sfp_instagram
# Purpose:     Gather information from Instagram profiles.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-07-11
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_instagram(SpiderFootPlugin):

    meta = {
        'name': "Instagram",
        'summary': "Gather information from Instagram profiles.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://www.instagram.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.instagram.com/developer/",
                "https://developers.facebook.com/docs/instagram-basic-display-api"
            ],
            'favIcon': "https://www.instagram.com/static/images/ico/favicon-192.png/68d99ba29cc8.png",
            'logo': "https://www.instagram.com/static/images/ico/favicon-192.png/68d99ba29cc8.png",
            'description': "Instagram is an American photo and video sharing social networking service.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['SOCIAL_MEDIA']

    def producedEvents(self):
        return ['RAW_RIR_DATA']

    def extractJson(self, html):
        m = r'<script type="application/ld\+json">(.+?)</script>'
        json_data = re.findall(m, html, re.MULTILINE | re.DOTALL)

        if not json_data:
            return None

        try:
            return json.loads(json_data[0])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Parse profile URL
        try:
            network = eventData.split(": ")[0]
            url = eventData.split(": ")[1].replace("<SFURL>", "").replace("</SFURL>", "")
        except Exception as e:
            self.debug(f"Unable to parse SOCIAL_MEDIA: {eventData} ({e})")
            return

        if network != 'Instagram':
            self.debug(f"Skipping social network profile, {url}, as not an Instagram profile")
            return

        # Retrieve profile
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.debug('No response from Instagram.com')
            return

        # Check if the profile is valid and extract profile data as JSON
        json_data = self.extractJson(res['content'])

        if not json_data:
            self.debug(f"{url} is not a valid Instagram profile")
            return

        e = SpiderFootEvent('RAW_RIR_DATA', str(json_data), self.__name__, event)
        self.notifyListeners(e)

# End of sfp_instagram class
