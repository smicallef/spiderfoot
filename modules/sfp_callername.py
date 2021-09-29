# -------------------------------------------------------------------------------
# Name:        sfp_callername
# Purpose:     SpiderFoot plug-in to search CallerName.com for a phone number
#              (US only) and retrieve location and reputation information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-28
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_callername(SpiderFootPlugin):

    meta = {
        'name': "CallerName",
        'summary': "Lookup US phone number location and reputation information.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "http://callername.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://callername.com/faq",
                "https://callername.com/stats"
            ],
            'favIcon': "http://static.callername.com/favicon.ico",
            'logo': "http://static.callername.com/img/logo.min.png",
            'description': "CallerName is a free, reverse phone lookup service for both cell and landline numbers. "
            "It relies on a database of white pages and business pages taken from public sources. "
            "The easy-to-use and streamlined interface allow users to look up the caller ID information of any number quickly. "
            "Just type the unknown number into the search bar to start. "
            "You need not pay nor register to use this 100% free service.",
        }
    }

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
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return ['GEOINFO', 'MALICIOUS_PHONE_NUMBER']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Only US numbers are supported (+1)
        if not eventData.startswith('+1'):
            self.debug('Unsupported phone number: ' + eventData)
            return

        # Strip country code (+1) and formatting
        number = eventData.lstrip('+1').strip('(').strip(')').strip('-').strip(' ')

        if not number.isdigit():
            self.debug('Invalid phone number: ' + number)
            return

        # Query CallerName.com for the specified phone number
        url = f"https://callername.com/{number}"
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.debug('No response from CallerName.com')
            return

        if res['code'] != '200':
            self.debug('No phone information found for ' + eventData)
            return

        location_match = re.findall(r'<div class="callerid"><h4>.*?</h4><p>(.+?)</p></div>', str(res['content']), re.MULTILINE | re.DOTALL)

        if location_match:
            location = location_match[0]

            if len(location) < 5 or len(location) > 100:
                self.debug("Skipping likely invalid location.")
            else:
                evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
                self.notifyListeners(evt)

        rep_good_match = re.findall(r'>SAFE.*?>(\d+) votes?<', str(res['content']))
        rep_bad_match = re.findall(r'>UNSAFE.*?>(\d+) votes?<', str(res['content']))

        if rep_good_match and rep_bad_match:
            good_votes = int(rep_good_match[0])
            bad_votes = int(rep_bad_match[0])

            if bad_votes > good_votes:
                text = f"CallerName [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent('MALICIOUS_PHONE_NUMBER', text, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_callername class
