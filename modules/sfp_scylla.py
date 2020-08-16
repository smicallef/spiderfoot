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
import time
import base64
import urllib.request, urllib.parse, urllib.error
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
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ 'DOMAIN_NAME' ]

    # What events this module produces
    def producedEvents(self):
        return [ 'EMAILADDR_COMPROMISED', 'PASSWORD_COMPROMISED', 'HASH_COMPROMISED', 'RAW_RIR_DATA' ]

    # Query Scylla API
    def query(self, qry, per_page=20, start=0):
        params = {
            'q': 'Email:@' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'num': str(per_page),
            'from': str(start)
        }

        b64_auth = base64.b64encode("sammy:BasicPassword!".encode("utf-8"))
        headers = {
            'Accept': 'application/json',
            # Provided by @_hyp3ri0n on Twitter, owner of the service and granted
            # permission to hard-code these.
            'Authorization': "Basic " + b64_auth.decode("utf-8")
        }
        res = self.sf.fetchUrl('https://scylla.sh/search?' + urllib.parse.urlencode(params),
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'],
                               # expired certficate
                               verify=False)

        time.sleep(self.opts['pause'])

        if res['code'] != "200":
            self.sf.error("Syclla.sh is having problems.", False)
            self.errorState = True
            return None

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

        if self.errorState:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        position = 0
        max_pages = int(self.opts['max_pages'])
        per_page = int(self.opts['per_page'])

        emails = list()
        hashes = list()
        passwords = list()

        while position < (per_page * max_pages):
            if self.checkForStop():
                return None

            if self.errorState:
                break

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

                if not self.sf.validEmail(email):
                    self.sf.debug("Skipping invalid email address: " + email)
                    continue

                mailDom = email.lower().split('@')[1]

                # Skip unrelated emails
                # Scylla sometimes returns broader results than the searched data
                if not self.getTarget().matches(mailDom):
                    self.sf.debug("Skipped address: " + email)
                    continue

                breach = source.get('Domain')

                if not breach:
                    breach = 'Unknown'

                emails.append(email + " [" + breach + "]")

                pass_hash = source.get('PassHash')

                if pass_hash:
                    pass_salt = source.get('PassSalt')
                    if pass_salt:
                        hashes.append(email + ':' + pass_hash + " (Salt: " + pass_salt + ") [" + breach + "]")
                    else:
                        hashes.append(email + ':' + pass_hash + " [" + breach + "]")

                password = source.get('Password')

                if password:
                    passwords.append(email + ':' + password + " [" + breach + "]")

            if len(data) < per_page:
                break

        for pass_hash in set(hashes):
            evt = SpiderFootEvent('HASH_COMPROMISED', pass_hash, self.__name__, event)
            self.notifyListeners(evt)

        for email in set(emails):
            evt = SpiderFootEvent('EMAILADDR_COMPROMISED', email, self.__name__, event)
            self.notifyListeners(evt)

        for password in set(passwords):
            evt = SpiderFootEvent('PASSWORD_COMPROMISED', password, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_scylla class
