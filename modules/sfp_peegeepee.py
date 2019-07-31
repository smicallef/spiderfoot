# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_peegeepee
# Purpose:     SpiderFoot plug-in for looking up e-mail addresses and domains
#              on PeeGeePee.com.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-07-07
# Copyright:   (c) bcoles
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import time
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_peegeepee(SpiderFootPlugin):
    """PeeGeePee:Footprint,Investigate,Passive:Public Registries::Look up e-mail addresses and domains on PeeGeePee.com."""

    # Default options
    opts = {
        'timeout': 15,
        'fetch_keys': False
    }

    # Option descriptions
    optdescs = {
        'timeout': 'Query timeout, in seconds.',
        'fetch_keys': 'Retrieve PGP keys for each match.'
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['EMAILADDR', 'DOMAIN_NAME', 'INTERNET_NAME']

    def producedEvents(self):
        return ['EMAILADDR', 'PGP_KEY', 'RAW_RIR_DATA']

    def query(self, qry):
        params = {
            'q': qry.encode('raw_unicode_escape')
        }

        res = self.sf.fetchUrl('https://peegeepee.com/search?' + urllib.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from PeeGeePee.com')
            return None

        result_html = re.findall('<ol class="numbered">(.+?)</ol>', res['content'], re.MULTILINE | re.DOTALL)

        if not result_html:
            self.sf.debug('No results from PeeGeePee.com')
            return None

        data = re.findall('<li>(.+?)</li>', result_html[0], re.DOTALL)

        if not data:
            self.sf.debug('No results from PeeGeePee.com')
            return None

        keys = dict()
        
        for key_data in data:
            fingerprint = re.findall('<code>(.+?)</code>', key_data)

            if not fingerprint:
                continue

            fingerprint = fingerprint[0].replace(' ', '')

            name_data = ' - '.join(key_data.split(' - ')[1:])

            if not name_data:
                continue

            description = '/'.join(name_data.split('/')[:-1])
            email = name_data.split('/')[-1]

            keys[fingerprint] = [description.strip(), email.strip()]

        return keys

    def retrieveKey(self, fingerprint, sourceEvent):
        res = self.sf.fetchUrl('https://d.peegeepee.com/' + fingerprint + '.asc',
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from d.PeeGeePee.com')
            return None

        pat = re.compile("(-----BEGIN.*END.*BLOCK-----)", re.MULTILINE | re.DOTALL)
        matches = re.findall(pat, res['content'])

        for match in matches:
            self.sf.debug('Found public key: ' + match)

            if len(match) < 300:
                self.sf.debug('Likely invalid public key.')
                continue

            evt = SpiderFootEvent('PGP_KEY', match, self.__name__, sourceEvent)
            self.notifyListeners(evt)

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if srcModuleName == 'sfp_peegeepee':
            self.sf.debug("Ignoring " + eventData + ", from self.")
            return None

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None

        self.results[eventData] = True

        keys = self.query(eventData)

        if not keys:
            self.sf.debug('No results found for ' + eventData)
            return None

        names = list()
        emails = list()

        for key in keys:
            name = keys.get(key)[0]
            email = keys.get(key)[1]

            if not email:
                continue

            # Get e-mail addresses on this domain
            if eventName == 'DOMAIN_NAME' or eventName == 'INTERNET_NAME':
                try:
                    mailDom = email.lower().split('@')[1]
                except IndexError:
                    continue

                if not self.getTarget().matches(mailDom):
                    continue

            # Retrieve names for the specified e-mail address
            if eventName == 'EMAILADDR':
                if not email.lower() == eventData.lower():
                    continue

            emails.append(email)
            names.append(name)

        for name in set(names):
            # A bit of a hack. Submit the description to sfp_names
            # and see if it is considered to be a name.
            evt = SpiderFootEvent('RAW_RIR_DATA', 'Possible full name: ' + name,
                                  self.__name__, event)
            self.notifyListeners(evt)

        for email in set(emails):
                evt = SpiderFootEvent('EMAILADDR', email, self.__name__, event)
                self.notifyListeners(evt)

        if self.opts['fetch_keys']:
            for key in keys:
                self.retrieveKey(key, event)
 
        return None

# End of sfp_peegeepee class
