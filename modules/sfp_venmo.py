#-------------------------------------------------------------------------------
# Name:        sfp_venmo
# Purpose:     Gather user information from Venmo API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-07-16
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_venmo(SpiderFootPlugin):
    """Venmo:Footprint,Investigate,Passive:Social Media::Gather user information from Venmo API."""

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
        return [ 'USERNAME' ]

    # What events this module produces
    def producedEvents(self):
        return [ 'RAW_RIR_DATA' ]

    # Query Venmo API
    def query(self, qry):
        res = self.sf.fetchUrl('https://api.venmo.com/v1/users/' + qry,
                               timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from api.venmo.com')
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        json_data = data.get('data')

        if not json_data:
            self.sf.debug(qry + " is not a valid Venmo username")
            return None

        return json_data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        data = self.query(eventData)

        if not data:
            return None

        e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(e)

        display_name = data.get('display_name')

        if display_name:
            evt = SpiderFootEvent('RAW_RIR_DATA',
                                  'Possible full name: ' + display_name,
                                  self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_venmo class
