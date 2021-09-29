# -------------------------------------------------------------------------------
# Name:        sfp_numverify
# Purpose:     SpiderFoot plug-in to search numverify.com API for a phone number
#              and retrieve location and carrier information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-25
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_numverify(SpiderFootPlugin):

    meta = {
        'name': "numverify",
        'summary': "Lookup phone number location and carrier information from numverify.com.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "http://numverify.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://numverify.com/documentation",
                "https://numverify.com/faq"
            ],
            'apiKeyInstructions': [
                "Visit https://numverify.com",
                "Sign up for a free account",
                "Navigate to https://numverify.com/dashboard",
                "The API key is listed under 'Your API Access Key'"
            ],
            'favIcon': "https://numverify.com/images/icons/numverify_shortcut_icon.ico",
            'logo': "https://numverify.com/images/logos/numverify_header.png",
            'description': "Global Phone Number Validation & Lookup JSON API.\n"
            "NumVerify offers a full-featured yet simple RESTful JSON API for "
            "national and international phone number validation and information lookup for a total of 232 countries around the world.\n"
            "Requested numbers are processed in real-time, cross-checked with the latest international numbering plan databases "
            "and returned in handy JSON format enriched with useful carrier, geographical location and line type data.",
        }
    }

    # Default options
    opts = {
        'api_key': ''
    }

    # Option descriptions
    optdescs = {
        'api_key': 'numverify API key.'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return ['RAW_RIR_DATA', 'GEOINFO', 'PROVIDER_TELCO']

    # Query numverify API for the specified phone number
    # https://numverify.com/documentation
    def query(self, qry):
        number = qry.strip('+').strip('(').strip(')')

        params = {
            'number': number.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'country_code': '',
            'format': '0',  # set to "1" for prettified debug output
            'access_key': self.opts['api_key']
        }

        # Free API does not support HTTPS for no adequately explained reason
        res = self.sf.fetchUrl("http://apilayer.net/api/validate?" + urllib.parse.urlencode(params),
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.debug('No response from apilayer.net')
            return None

        if res['code'] == '101':
            self.error('API error: invalid API key')
            self.errorState = True
            return None

        if res['code'] == '102':
            self.error('API error: user account deactivated')
            self.errorState = True
            return None

        if res['code'] == '104':
            self.error('API error: usage limit exceeded')
            self.errorState = True
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if data.get('error') is not None:
            self.error('API error: ' + str(data.get('error')))
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_numverify but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        data = self.query(eventData)

        if data is None:
            self.debug("No phone information found for " + eventData)
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        if data.get('country_code'):
            country = self.sf.countryNameFromCountryCode(data.get('country_code'))
            location = ', '.join([_f for _f in [data.get('location'), country] if _f])
            evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.debug("No location information found for " + eventData)

        if data.get('carrier'):
            evt = SpiderFootEvent("PROVIDER_TELCO", data.get('carrier'), self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.debug("No carrier information found for " + eventData)

# End of sfp_numverify class
