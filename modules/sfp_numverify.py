#-------------------------------------------------------------------------------
# Name:        sfp_numverify
# Purpose:     SpiderFoot plug-in to search numverify.com API for a phone number
#              and retrieve location and carrier information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-25
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import urllib
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_numverify(SpiderFootPlugin):
    """numverify:Footprint,Investigate,Passive:Real World:apikey:Lookup phone number location and carrier information from numverify.com."""

    # Default options
    opts = {
        'api_key': ''
    }

    # Option descriptions
    optdescs = {
        'api_key': 'numverify API key.'
    }

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "numverify"
        self.results = dict()
        self.errorState = False

        for opt in userOpts.keys():
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
            'number': number.encode('raw_unicode_escape'),
            'country_code': '',
            'format': '0', # set to "1" for prettified debug output
            'access_key': self.opts['api_key']
        }

        # Free API does not support HTTPS for no adequately explained reason
        res = self.sf.fetchUrl("http://apilayer.net/api/validate?" + urllib.urlencode(params),
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from apilayer.net')
            return None

        if res['code'] == '101':
            self.sf.error('API error: invalid API key', False)
            self.errorState = True
            return None

        if res['code'] == '102':
            self.sf.error('API error: user account deactivated', False)
            self.errorState = True
            return None

        if res['code'] == '104':
            self.sf.error('API error: usage limit exceeded', False)
            self.errorState = True
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        if data.get('error') is not None:
            self.sf.error('API error: ' + str(data.get('error')), False)
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_numverify but did not set an API key!", False)
            self.errorState = True
            return None

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        data = self.query(eventData)

        if data is None:
            self.sf.debug("No phone information found for " + eventData)
            return None

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        if data.get('country_code') is not None:
            location = ', '.join(filter(None, [data.get('location'), data.get('country_code')]))
            evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.sf.debug("No location information found for " + eventData)

        if data.get('carrier') is not None:
            evt = SpiderFootEvent("PROVIDER_TELCO", data.get('carrier'), self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.sf.debug("No carrier information found for " + eventData)

# End of sfp_numverify class
