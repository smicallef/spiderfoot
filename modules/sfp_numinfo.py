#-------------------------------------------------------------------------------
# Name:        sfp_numinfo
# Purpose:     SpiderFoot plug-in to search numinfo.net for a phone number
#              and retrieve email address.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-28
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import re
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_numinfo(SpiderFootPlugin):
    """numinfo:Footprint,Investigate,Passive:Real World:slow:Lookup phone number information from numinfo.net."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = 'numinfo'
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return ['RAW_RIR_DATA', 'EMAILADDR', 'AFFILIATE_EMAILADDR']

    # Query numinfo for the specified phone number
    def query(self, qry):
        number = qry.strip('+').strip('(').strip(')').strip('-').strip(' ')

        if not number.isdigit():
            self.sf.debug('Invalid phone number: ' + number)
            return None

        res = self.sf.fetchUrl("http://" + number + '.numinfo.net/',
                               timeout=60,
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from numinfo.net')
            return None

        if res['code'] != '200':
            return None

        json_data = re.findall(r'<script type="application/ld\+json">(.+?)</script>',
                               res['content'], re.MULTILINE | re.DOTALL)

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

        data = self.query(eventData)

        if data is None:
            self.sf.debug('No phone information found for ' + eventData)
            return None

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        if data.get('email'):
            email_match = re.findall(r'^mailto:([a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)$', data.get('email'))
            if email_match:
                mailDom = email_match[0].lower().split('@')[1]
                if not self.getTarget().matches(mailDom):
                    evttype = "AFFILIATE_EMAILADDR"
                else:
                    evttype = "EMAILADDR"

                evt = SpiderFootEvent(evttype, email_match[0], self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_numinfo class
