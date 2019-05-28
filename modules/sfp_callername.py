#-------------------------------------------------------------------------------
# Name:        sfp_callername
# Purpose:     SpiderFoot plug-in to search CallerName.com for a phone number
#              (US only) and retrieve location and reputation information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-28
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_callername(SpiderFootPlugin):
    """CallerName:Footprint,Investigate,Passive:Real World::Lookup US phone number location and reputation information."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = 'CallerName'
        self.results = dict()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return ['GEOINFO', 'MALICIOUS_PHONE_NUMBER']

    # Query numinfo for the specified phone number
    def query(self, qry):
        number = qry.lstrip('+1').strip('(').strip(')').strip('-').strip(' ')

        if not number.isdigit():
            self.sf.debug('Invalid phone number: ' + number)
            return None

        res = self.sf.fetchUrl("https://callername.com/" + number,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from CallerName.com')
            return None

        if res['code'] != '200':
            return None

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if not eventData.startswith('+1'):
            self.sf.debug('Unsupported phone number: ' + eventData)
            return None

        html = self.query(eventData)

        if html is None:
            self.sf.debug('No phone information found for ' + eventData)
            return None

        location_match = re.findall(r'<div class="callerid"><h4>.*?</h4><p>(.+?)</p></div>', html, re.MULTILINE | re.DOTALL)

        if location_match is not None:
            location = location_match[0]

            if len(location) < 5 or len(location) > 100:
                self.sf.debug("Skipping likely invalid location.")
            else:
                evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
                self.notifyListeners(evt)

        rep_good_match = re.findall(r'>SAFE.*?>(\d+) votes?<', html)
        rep_bad_match = re.findall(r'>UNSAFE.*?>(\d+) votes?<', html)

        if rep_good_match is not None and rep_bad_match is not None:
            good_votes = int(rep_good_match[0])
            bad_votes = int(rep_bad_match[0])

            if bad_votes > good_votes:
                evt = SpiderFootEvent('MALICIOUS_PHONE_NUMBER', eventData, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_callername class
