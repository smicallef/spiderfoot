#-------------------------------------------------------------------------------
# Name:        sfp_numpi
# Purpose:     SpiderFoot plug-in to search numpi.com for a phone number
#              (USA / Canada only) and retrieve carrier and location information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-31
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_numpi(SpiderFootPlugin):
    """numpi:Footprint,Investigate,Passive:Real World::Lookup USA/Canada phone number location and carrier information from numpi.com."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = 'numpi'
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return ['RAW_RIR_DATA', 'GEOINFO', 'PROVIDER_TELCO']

    # Query numpi for the specified phone number
    def query(self, qry):
        res = self.sf.fetchUrl('https://numpi.com/phone-info/' + qry,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from numpi.com')
            return None

        if res['code'] != '200':
            return None

        table = re.findall(r'<table id="body_in_phone_info">(.+?)</table>',
                          res['content'], re.MULTILINE | re.DOTALL)

        if not table:
            return None

        name_html = re.findall(r'<div class="body_in_phone_id">(.+?)</div>',
                          res['content'], re.MULTILINE | re.DOTALL)

        data = dict()

        if name_html:
            name = name_html[0].strip()

            if len(name) < 100:
                data['Name'] = name

        for row in re.findall('<tr>(.+?)</tr>', table[0]):
            cols = re.findall('<td>(.+?)</td>', row)

            if len(cols) != 2:
                continue

            k, v = cols

            if v.startswith('Not available'):
                continue

            # Malformed data. Perhaps the HTML layout has changed.
            if len(k) > 100 or len(v) > 100:
                continue

            data[k.strip('*')] = v.strip()

        return data

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

        # Only USA / Canada numbers are supported (+1)
        if not eventData.startswith('+1'):
            self.sf.debug('Unsupported phone number: ' + eventData)
            return None

        # Strip country code (+1) and formatting
        number = eventData.lstrip('+1').strip('(').strip(')').strip('-').strip(' ')

        if not number.isdigit():
            self.sf.debug('Invalid phone number: ' + number)
            return None

        # Query numpi.com for the specified phone number
        data = self.query(number)

        if data is None:
            self.sf.debug('No phone information found for ' + number)
            return None

        evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(evt)

        carrier = data.get('Carrier')
        if carrier:
            evt = SpiderFootEvent('PROVIDER_TELCO', carrier, self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.sf.debug("No carrier information found for " + eventData)

        location = ', '.join(filter(None, [data.get('City'), data.get('County'), data.get('State'), data.get('ZIP Code')]))
        if location:
            evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.sf.debug("No location information found for " + eventData)

# End of sfp_numpi class
