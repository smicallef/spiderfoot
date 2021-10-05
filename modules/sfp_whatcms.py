# -------------------------------------------------------------------------------
# Name:        sfp_whatcms
# Purpose:     SpiderFoot plug-in to check which web technology is used
#              on a target website using WhatCMS API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-06-01
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_whatcms(SpiderFootPlugin):

    meta = {
        'name': "WhatCMS",
        'summary': "Check web technology using WhatCMS.org API.",
        'flags': ["apikey", "slow"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "https://whatcms.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://whatcms.org/API",
                "https://whatcms.org/Documentation"
            ],
            'apiKeyInstructions': [
                "Visit https://whatcms.org/API",
                "Register a free account",
                "Navigate to https://whatcms.org/APIKey",
                "The API key is listed under 'Your API Key'"
            ],
            'favIcon': "https://whatcms.org/themes/what_bootstrap4/favicon.ico",
            'logo': "https://whatcms.org/themes/what_bootstrap4/favicon.ico",
            'description': "Detect what CMS a site is using.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        # WhatCMS allows up to 20 seconds for responses to complete
        'timeout': 25,
        # Plans - https://whatcms.org/Subscriptions?cmd=PlanOptions
        # Free:   1 request per 10 seconds
        # $10/mo: 1 request per 5 seconds
        # $20/mo: 1 request per 2 seconds
        # $40/mo: 1 request per second
        'delay': 10
    }

    # Option descriptions
    optdescs = {
        'api_key': 'WhatCMS API key',
        'timeout': 'Query timeout, in seconds.',
        'delay': 'Delay between requests, in seconds.'
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
        return ['RAW_RIR_DATA', 'WEBSERVER_TECHNOLOGY']

    # Query WhatCMS API for the CMS used by the specified URL
    # https://whatcms.org/Documentation
    def queryCmsDetect(self, qry):
        params = {
            'url': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'key': self.opts['api_key']
        }

        res = self.sf.fetchUrl('https://whatcms.org/APIEndpoint/Detect?' + urllib.parse.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query WhatCMS API for the web technology used by the specified URL
    # https://whatcms.org/Documentation
    def queryCmsTechnology(self, qry):
        params = {
            'url': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'key': self.opts['api_key']
        }

        res = self.sf.fetchUrl('https://whatcms.org/APIEndpoint/Technology?' + urllib.parse.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Parse API response
    def parseApiResponse(self, res):
        if res['content'] is None:
            self.debug('No response from WhatCMS.org')
            return None

        if res['code'] != '200':
            self.error('Unexpected reply from WhatCMS.org: ' + res['code'])
            self.errorState = True
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        result = data.get('result')
        if result is None:
            self.error('API error: no results')
            return None

        code = str(result.get('code'))

        if code == '0':
            self.error('API error: Server failure')
            self.errorState = True
            return None

        if code == '101':
            self.error('API error: Invalid API Key')
            self.errorState = True
            return None

        if code == '102':
            self.error('API error: Unauthenticated request. Invalid API key?')
            self.errorState = True
            return None

        if code == '111':
            self.error('API error: Invalid URL')
            self.errorState = True
            return None

        if code == '120':
            self.error('API error: Too many requests')
            self.errorState = True
            return None

        if code == '121':
            self.error('API error: You have exceeded your monthly request quota')
            self.errorState = True
            return None

        if code == '123':
            self.error('API error: Account disabled per violation of Terms and Conditions')
            self.errorState = True
            return None

        if code == '201':
            self.error('API error: CMS or Host not found')
            self.errorState = True
            return None

        if code != '200':
            self.error('Unexpected status code from WhatCMS.org: ' + code)
            self.errorState = True
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == '':
            self.error('You enabled sfp_whatcms but did not set an API key!')
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        data = self.queryCmsTechnology(eventData)

        if data is None:
            self.debug('No web technology found for ' + eventData)
            return

        results = data.get('results')

        if results is None:
            self.debug('No web technology found for ' + eventData)
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', str(results), self.__name__, event)
        self.notifyListeners(evt)

        for result in results:
            if result.get('name'):
                software = ' '.join([_f for _f in [result.get('name'), result.get('version')] if _f])
                evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', software, self.__name__, event)
                self.notifyListeners(evt)
            else:
                self.debug('No web technology found for ' + eventData)

# End of sfp_whatcms class
