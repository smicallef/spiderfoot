# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_phone
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) to identify phone numbers, and
#               lookup carrier information in Google's libphonenumber DB.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/06/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     GPL
# -------------------------------------------------------------------------------

import phonenumbers
from phonenumbers import carrier
#from phonenumbers import geocoder
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_phone(SpiderFootPlugin):
    """Phone Numbers:Passive,Footprint,Investigate:Real World::Identify phone numbers in scraped webpages."""



    # Default options
    opts = {}

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['TARGET_WEB_CONTENT', 'DOMAIN_WHOIS', 'NETBLOCK_WHOIS', 'PHONE_NUMBER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ['PHONE_NUMBER', 'PROVIDER_TELCO']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.sf.hashstring(eventData)

        if sourceData in self.results:
            return None
        else:
            self.results.append(sourceData)

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName in ['TARGET_WEB_CONTENT', 'DOMAIN_WHOIS', 'NETBLOCK_WHOIS']:
            # Make potential phone numbers more friendly to parse
            content = eventData.replace('.','-')

            for match in phonenumbers.PhoneNumberMatcher(content, region=None):
                n = phonenumbers.format_number(match.number,
                                           phonenumbers.PhoneNumberFormat.E164)
                evt = SpiderFootEvent("PHONE_NUMBER", n, self.__name__, event)
                if event.moduleDataSource:
                    evt.moduleDataSource = event.moduleDataSource
                else:
                    evt.moduleDataSource = "Unknown"
                self.notifyListeners(evt)

        if eventName == 'PHONE_NUMBER':
            try:
                number = phonenumbers.parse(eventData)
            except BaseException as e:
                self.sf.debug('Error parsing phone number: ' + str(e))
                return None

            try:
                number_carrier = carrier.name_for_number(number, 'en')
            except BaseException as e:
                self.sf.debug('Error retrieving phone number carrier: ' + str(e))
                return None

            if number_carrier:
                evt = SpiderFootEvent("PROVIDER_TELCO", number_carrier, self.__name__, event)
                self.notifyListeners(evt)
            else:
                self.sf.debug("No carrier information found for " + eventData)

            #try:
            #    location = geocoder.description_for_number(number, 'en')
            #except BaseException as e:
            #    self.sf.debug('Error retrieving phone number location: ' + str(e))
            #    return None

            #if location:
            #    evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            #    self.notifyListeners(evt)
            #else:
            #    self.sf.debug("No location information found for " + eventData)

        return None

# End of sfp_phone class
