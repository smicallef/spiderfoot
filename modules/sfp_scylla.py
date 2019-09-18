#-------------------------------------------------------------------------------
# Name:        sfp_scylla
# Purpose:     Gather breach data from Scylla API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-06
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import re
import time
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_scylla(SpiderFootPlugin):
    """Scylla:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Gather breach data from Scylla API."""

    # Default options
    opts = {
        'pause': 3,
        'per_page': 20,
        'max_pages': 20
    }

    # Option descriptions
    optdescs = {
        'pause':     "Number of seconds to pause between fetches.",
        'per_page':  "Maximum number of results per page.",
        'max_pages': "Maximum number of pages of results to fetch."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ 'INTERNET_NAME' ]

    # What events this module produces
    def producedEvents(self):
        return [ 'EMAILADDR_COMPROMISED', 'PASSWORD_COMPROMISED', 'HASH_COMPROMISED', 'RAW_RIR_DATA' ]

    # Query Scylla API
    def query(self, qry, per_page=20, start=0):
        params = {
            'q': 'Email:@' + qry.encode('raw_unicode_escape'),
            'num': str(per_page),
            'from': str(start)
        }

        headers = {
            'Accept': 'application/json',
        }
        res = self.sf.fetchUrl('https://scylla.sh/search?' + urllib.urlencode(params),
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['pause'])

        if res['content'] is None:
            self.sf.debug('No response from Scylla.sh')
            return None

        try:
            data = json.loads(res['content'])
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

        position = 0
        max_pages = int(self.opts['max_pages'])
        per_page = int(self.opts['per_page'])

        while position < (per_page * max_pages):
            data = self.query(eventData, per_page, position)

            if not data:
                return None

            position += per_page

            #evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            #self.notifyListeners(evt)

            for result in data:
                source = result.get('_source')

                if not source:
                    continue

                email = source.get('Email')

                # A blank email result should not be possible, as we searched using the 'Email:' filter
                if not email:
                    continue

                # Skip unrelated emails
                # Scylla sometimes returns broader results than the searched data
                mailDom = email.lower().split('@')[1]
                if not self.getTarget().matches(mailDom):
                    self.sf.debug("Skipped address: " + match)
                    continue

                breach = source.get('Domain')

                if not breach:
                    breach = 'Unknown'

                evt = SpiderFootEvent('EMAILADDR_COMPROMISED', email + " [" + breach + "]", self.__name__, event)
                self.notifyListeners(evt)

                pass_hash = source.get('PassHash')

                if pass_hash:
                    pass_salt = source.get('PassSalt')
                    if pass_salt:
                        evt = SpiderFootEvent('HASH_COMPROMISED', email + ':' + pass_hash + " (Salt: " + pass_salt + ") [" + breach + "]", self.__name__, event)
                    else:
                        evt = SpiderFootEvent('HASH_COMPROMISED', email + ':' + pass_hash + " [" + breach + "]", self.__name__, event)
                    self.notifyListeners(evt)

                password = source.get('Password')

                if password:
                    evt = SpiderFootEvent('PASSWORD_COMPROMISED', email + ':' + password + " [" + breach + "]", self.__name__, event)
                    self.notifyListeners(evt)

            if len(data) < per_page:
                break

# End of sfp_scylla class
