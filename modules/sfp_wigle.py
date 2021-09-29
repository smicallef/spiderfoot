# -------------------------------------------------------------------------------
# Name:         sfp_wigle
# Purpose:      Query wigle.net to identify nearby WiFi access points.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     10/09/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_wigle(SpiderFootPlugin):

    meta = {
        'name': "WiGLE",
        'summary': "Query WiGLE to identify nearby WiFi access points.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://wigle.net/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://api.wigle.net/",
                "https://api.wigle.net/swagger"
            ],
            'apiKeyInstructions': [
                "Visit https://wigle.net/",
                "Register a free account",
                "Navigate to https://wigle.net/account",
                "Click on 'Show my token'",
                "The API key is listed under 'API Token'"
            ],
            'favIcon': "https://wigle.net/favicon.ico?v=A0Ra9gElOR",
            'logo': "https://wigle.net/images/planet-bubble.png",
            'description': "We consolidate location and information of wireless networks world-wide to a central database, "
            "and have user-friendly desktop and web applications that can map, "
            "query and update the database via the web.",
        }
    }

    # Default options
    opts = {
        "api_key_encoded": "",
        "days_limit": "365",
        "variance": "0.01"
    }

    # Option descriptions
    optdescs = {
        "api_key_encoded": "Wigle.net base64-encoded API name/token pair.",
        "days_limit": "Maximum age of data to be considered valid.",
        "variance": "How tightly to bound queries against the latitude/longitude box extracted from idenified addresses. This value must be between 0.001 and 0.2."

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
        return ["PHYSICAL_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["WIFI_ACCESS_POINT"]

    def getcoords(self, qry):
        params = {
            'addresscode': qry.encode('utf-8', errors='replace')
        }
        hdrs = {
            "Accept": "application/json",
            "Authorization": "Basic " + self.opts['api_key_encoded']
        }

        res = self.sf.fetchUrl(
            "https://api.wigle.net/api/v2/network/geocode?" + urllib.parse.urlencode(params),
            timeout=30,
            useragent="SpiderFoot",
            headers=hdrs
        )

        if res['code'] == "404" or not res['content']:
            return None

        if "too many queries" in res['content']:
            self.error("Wigle.net query limit reached for the day.")
            return None

        try:
            info = json.loads(res['content'])
            if len(info.get('results', [])) == 0:
                return None
            return info['results'][0]['boundingbox']
        except Exception as e:
            self.error(f"Error processing JSON response from Wigle.net: {e}")
            return None

    def getnetworks(self, coords):
        params = {
            'onlymine': 'false',
            'latrange1': str(coords[0]),
            'latrange2': str(coords[1]),
            'longrange1': str(coords[2]),
            'longrange2': str(coords[3]),
            'freenet': 'false',
            'paynet': 'false',
            'variance': self.opts['variance']
        }

        if self.opts['days_limit'] != "0":
            dt = datetime.datetime.now() - datetime.timedelta(days=int(self.opts['days_limit']))
            date_calc = dt.strftime("%Y%m%d")
            params['lastupdt'] = date_calc

        hdrs = {
            "Accept": "application/json",
            "Authorization": "Basic " + self.opts['api_key_encoded']
        }

        res = self.sf.fetchUrl(
            "https://api.wigle.net/api/v2/network/search?" + urllib.parse.urlencode(params),
            timeout=30,
            useragent="SpiderFoot",
            headers=hdrs
        )

        if res['code'] == "404" or not res['content']:
            return None

        if "too many queries" in res['content']:
            self.error("Wigle.net query limit reached for the day.")
            return None

        ret = list()
        try:
            info = json.loads(res['content'])

            if len(info.get('results', [])) == 0:
                return None

            for r in info['results']:
                if None not in [r['ssid'], r['netid']]:
                    ret.append(r['ssid'] + " (Net ID: " + r['netid'] + ")")

            return ret
        except Exception as e:
            self.error(f"Error processing JSON response from WiGLE: {e}")
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key_encoded'] == "":
            self.error("You enabled sfp_wigle but did not set an API key!")
            self.errorState = True
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        coords = self.getcoords(eventData)
        if not coords:
            self.error("Couldn't get coordinates for address from Wigle.net.")
            return

        nets = self.getnetworks(coords)
        if not nets:
            self.error("Couldn't get networks for coordinates from Wigle.net.")
            return

        for n in nets:
            e = SpiderFootEvent("WIFI_ACCESS_POINT", n, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_wigle class
