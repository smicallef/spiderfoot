#-------------------------------------------------------------------------------
# Name:        sfp_whatcms
# Purpose:     SpiderFoot plug-in to check which web technology is used
#              on a target website using WhatCMS API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-06-01
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import urllib
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_whatcms(SpiderFootPlugin):
    """WhatCMS:Footprint,Investigate:Content Analysis:apikey,slow:Check web technology using WhatCMS.org API."""

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

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = 'WhatCMS'
        self.results = dict()
        self.errorState = False

        for opt in userOpts.keys():
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
            'url': qry,
            'key': self.opts['api_key']
        }

        res = self.sf.fetchUrl('https://whatcms.org/APIEndpoint/Detect?' + urllib.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query WhatCMS API for the web technology used by the specified URL
    # https://whatcms.org/Documentation
    def queryCmsTechnology(self, qry):
        params = {
            'url': qry,
            'key': self.opts['api_key']
        }

        res = self.sf.fetchUrl('https://whatcms.org/APIEndpoint/Technology?' + urllib.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Parse API response
    def parseApiResponse(self, res):
        if res['content'] is None:
            self.sf.debug('No response from WhatCMS.org')
            return None

        if res['code'] != '200':
            self.sf.error('Unexpected reply from WhatCMS.org: ' + res['code'], False)
            self.errorState = True
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        result = data.get('result')
        if result is None:
            self.sf.error('API error: no results', False)
            return None

        code = str(result.get('code'))

        if code == '0':
            self.sf.error('API error: Server failure', False)
            self.errorState = True
            return None

        if code == '101':
            self.sf.error('API error: Invalid API Key', False)
            self.errorState = True
            return None

        if code == '102':
            self.sf.error('API error: Unauthenticated request. Invalid API key?', False)
            self.errorState = True
            return None

        if code == '111':
            self.sf.error('API error: Invalid URL', False)
            self.errorState = True
            return None

        if code == '120':
            self.sf.error('API error: Too many requests', False)
            self.errorState = True
            return None

        if code == '121':
            self.sf.error('API error: You have exceeded your monthly request quota', False)
            self.errorState = True
            return None

        if code == '123':
            self.sf.error('API error: Account disabled per violation of Terms and Conditions', False)
            self.errorState = True
            return None

        if code == '201':
            self.sf.error('API error: CMS or Host not found', False)
            self.errorState = True
            return None

        if code != '200':
            self.sf.error('Unexpected status code from WhatCMS.org: ' + code, False)
            self.errorState = True
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts['api_key'] == '':
            self.sf.error('You enabled sfp_whatcms but did not set an API key!', False)
            self.errorState = True
            return None

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        data = self.queryCmsTechnology(eventData)

        if data is None:
            self.sf.debug('No web technology found for ' + eventData)
            return None

        results = data.get('results')

        if results is None:
            self.sf.debug('No web technology found for ' + eventData)
            return None

        evt = SpiderFootEvent('RAW_RIR_DATA', str(results), self.__name__, event)
        self.notifyListeners(evt)

        for result in results:
            if result.get('name'):
                software = ' '.join(filter(None, [result.get('name'), result.get('version')]))
                evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', software, self.__name__, event)
                self.notifyListeners(evt)
            else:
                self.sf.debug('No web technology found for ' + eventData)

# End of sfp_whatcms class
