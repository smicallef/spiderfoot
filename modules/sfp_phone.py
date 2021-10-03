# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_phone
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
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

# from phonenumbers import geocoder
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_phone(SpiderFootPlugin):

    meta = {
        'name': "Phone Number Extractor",
        'summary': "Identify phone numbers in scraped webpages.",
        'flags': [],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Content Analysis"]
    }

    opts = {}

    results = None
    optdescs = {}

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['TARGET_WEB_CONTENT', 'DOMAIN_WHOIS', 'NETBLOCK_WHOIS', 'PHONE_NUMBER']

    def producedEvents(self):
        return ['PHONE_NUMBER', 'PROVIDER_TELCO']

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.sf.hashstring(eventData)

        if sourceData in self.results:
            return

        self.results[sourceData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName in ['TARGET_WEB_CONTENT', 'DOMAIN_WHOIS', 'NETBLOCK_WHOIS']:
            # Make potential phone numbers more friendly to parse
            content = eventData.replace('.', '-')

            for match in phonenumbers.PhoneNumberMatcher(content, region=None):
                n = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
                evt = SpiderFootEvent("PHONE_NUMBER", n, self.__name__, event)
                if event.moduleDataSource:
                    evt.moduleDataSource = event.moduleDataSource
                else:
                    evt.moduleDataSource = "Unknown"
                self.notifyListeners(evt)

        if eventName == 'PHONE_NUMBER':
            try:
                number = phonenumbers.parse(eventData)
            except Exception as e:
                self.debug(f"Error parsing phone number: {e}")
                return

            try:
                number_carrier = carrier.name_for_number(number, 'en')
            except Exception as e:
                self.debug(f"Error retrieving phone number carrier: {e}")
                return

            if not number_carrier:
                self.debug(f"No carrier information found for {eventData}")
                return

            evt = SpiderFootEvent("PROVIDER_TELCO", number_carrier, self.__name__, event)

            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"

            self.notifyListeners(evt)

            # try:
            #     location = geocoder.description_for_number(number, 'en')
            # except Exception as e:
            #     self.debug('Error retrieving phone number location: ' + str(e))
            #     return

            # if location:
            #     evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            #     self.notifyListeners(evt)
            # else:
            #     self.debug("No location information found for " + eventData)

# End of sfp_phone class
