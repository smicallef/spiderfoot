# -------------------------------------------------------------------------------
# Name:        sfp_scylla
# Purpose:     Gather breach data from Scylla API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-06
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_scylla(SpiderFootPlugin):

    meta = {
        'name': "Scylla",
        'summary': "Gather breach data from Scylla API.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://scylla.so/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://scylla.so/crowdsource"
            ],
            'favIcon': "",
            'logo': "",
            'description': "scylla.so has two major goals. One is to have a community-oriented database leak community "
            "that is a useful tool for security researchers.\n"
            "The other major goal is to undercut those people that are selling databases.",
        }
    }

    # Default options
    opts = {
        'pause': 3,
        'per_page': 20,
        'max_pages': 20
    }

    # Option descriptions
    optdescs = {
        'pause': "Number of seconds to pause between fetches.",
        'per_page': "Maximum number of results per page.",
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
        return ['DOMAIN_NAME']

    # What events this module produces
    def producedEvents(self):
        return ['EMAILADDR_COMPROMISED', 'PASSWORD_COMPROMISED', 'HASH_COMPROMISED', 'RAW_RIR_DATA']

    # Query Scylla API
    def query(self, qry, per_page=20, start=0):
        params = {
            'q': 'email:@' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'size': str(per_page),
            'start': str(start)
        }

        headers = {
            'Accept': 'application/json'
        }
        res = self.sf.fetchUrl(f"https://scylla.so/search?{urllib.parse.urlencode(params)}",
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'],
                               # expired certficate
                               verify=False)

        time.sleep(self.opts['pause'])

        if res['code'] != "200":
            self.error("Syclla.sh is having problems.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.debug('No response from Scylla.so')
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        if self.errorState:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        position = 0
        max_pages = int(self.opts['max_pages'])
        per_page = int(self.opts['per_page'])

        emails = list()
        hashes = list()
        passwords = list()

        while position < (per_page * max_pages):
            if self.checkForStop():
                return

            if self.errorState:
                break

            data = self.query(eventData, per_page, position)

            if not data:
                return

            position += per_page

            # evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            # self.notifyListeners(evt)

            for row in data:
                result = row.get('fields')

                if not result:
                    continue

                email = result.get('email')

                # A blank email result should not be possible, as we searched using the 'Email:' filter
                if not email:
                    continue

                if not self.sf.validEmail(email):
                    self.debug("Skipping invalid email address: " + email)
                    continue

                mailDom = email.lower().split('@')[1]

                # Skip unrelated emails
                # Scylla sometimes returns broader results than the searched data
                if not self.getTarget().matches(mailDom):
                    self.debug("Skipped address: " + email)
                    continue

                breach = result.get('domain', 'Unknown')
                emails.append(email + " [" + breach + "]")
                pass_hash = result.get('passhash')

                if pass_hash:
                    pass_salt = result.get('passsalt')
                    if pass_salt:
                        hashes.append(email + ':' + pass_hash + " (Salt: " + pass_salt + ") [" + breach + "]")
                    else:
                        hashes.append(email + ':' + pass_hash + " [" + breach + "]")

                password = result.get('password')

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
