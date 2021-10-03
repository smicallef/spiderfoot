# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_countryname
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
#               modules (such as sfp_iban, sfp_phone, sfp_whois) and identifying country names
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     28/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

import phonenumbers
from phonenumbers.phonenumberutil import region_code_for_country_code

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_countryname(SpiderFootPlugin):

    meta = {
        'name': "Country Name Extractor",
        'summary': "Identify country names in any obtained data.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {
        'cohosted': True,
        'affiliate': True,
        'noncountrytld': True,
        'similardomain': False,
    }

    optdescs = {
        'cohosted': "Obtain country name from co-hosted sites",
        'affiliate': "Obtain country name from affiliate sites",
        'noncountrytld': "Parse TLDs not associated with any country as default country domains",
        'similardomain': "Obtain country name from similar domains"
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def detectCountryFromPhone(self, srcPhoneNumber):
        """Lookup name of country from phone number region code.

        Args:
            srcPhoneNumber (str): phone number

        Returns:
            str: country name
        """

        if not isinstance(srcPhoneNumber, str):
            return None

        try:
            phoneNumber = phonenumbers.parse(srcPhoneNumber)
        except Exception:
            self.debug(f"Skipped invalid phone number: {srcPhoneNumber}")
            return None

        try:
            countryCode = region_code_for_country_code(phoneNumber.country_code)
        except Exception:
            self.debug(f"Lookup of region code failed for phone number: {srcPhoneNumber}")
            return None

        if not countryCode:
            return None

        return self.sf.countryNameFromCountryCode(countryCode.upper())

    def detectCountryFromDomainName(self, srcDomain):
        """Lookup name of country from TLD of domain name.

        Args:
            srcDomain (str): domain

        Returns:
            str: country name
        """
        if not isinstance(srcDomain, str):
            return None

        # Split domain into parts by '.'
        # Country TLDs are reserved
        domainParts = srcDomain.split(".")

        # Search for country TLD in the domain parts - reversed
        for part in domainParts[::-1]:
            country_name = self.sf.countryNameFromTld(part)
            if country_name:
                return country_name

        return None

    def detectCountryFromIBAN(self, srcIBAN):
        """Detect name of country from IBAN.

        Args:
            srcIBAN (str): IBAN

        Returns:
            str: country name
        """
        if not isinstance(srcIBAN, str):
            return None

        return self.sf.countryNameFromCountryCode(srcIBAN[0:2])

    def detectCountryFromData(self, srcData):
        """Detect name of country from event data (WHOIS lookup, Geo Info, Physical Address, etc)

        Args:
            srcData (str): event data

        Returns:
            list: list of countries
        """
        countries = list()

        if not srcData:
            return countries

        # Get dictionary of country codes and  country names
        abbvCountryCodes = self.sf.getCountryCodeDict()

        # Look for countrycodes and country in source data
        for countryName in abbvCountryCodes.values():
            if countryName.lower() not in srcData.lower():
                continue

            # Look for country name in source data
            # Spaces are not included since "New Jersey" and others
            # will get interpreted as "Jersey", etc.
            matchCountries = re.findall(r"[,'\"\:\=\[\(\[\n\t\r\.] ?" + countryName + r"[,'\"\:\=\[\(\[\n\t\r\.]", srcData, re.IGNORECASE)

            if matchCountries:
                countries.append(countryName)

        # Look for "Country: ", usually found in Whois records
        matchCountries = re.findall("country: (.+?)", srcData, re.IGNORECASE)
        if matchCountries:
            for m in matchCountries:
                m = m.strip()
                if m in abbvCountryCodes:
                    countries.append(abbvCountryCodes[m])
                if m in abbvCountryCodes.values():
                    countries.append(m)

        return list(set(countries))

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IBAN_NUMBER", "PHONE_NUMBER", "AFFILIATE_DOMAIN_NAME",
                "CO_HOSTED_SITE_DOMAIN", "DOMAIN_NAME", "SIMILARDOMAIN",
                "AFFILIATE_DOMAIN_WHOIS", "CO_HOSTED_SITE_DOMAIN_WHOIS",
                "DOMAIN_WHOIS", "GEOINFO", "PHYSICAL_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["COUNTRY_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if event.moduleDataSource:
            moduleDataSource = event.moduleDataSource
        else:
            moduleDataSource = "Unknown"

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        eventDataHash = self.sf.hashstring(eventData)

        if eventDataHash in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventDataHash] = True

        countryNames = list()

        # Process the event data based on incoming event type
        if eventName == "PHONE_NUMBER":
            countryNames.append(self.detectCountryFromPhone(eventData))
        elif eventName == "DOMAIN_NAME":
            countryNames.append(self.detectCountryFromDomainName(eventData))
        elif eventName == "AFFILIATE_DOMAIN_NAME" and self.opts["affiliate"]:
            countryNames.append(self.detectCountryFromDomainName(eventData))
        elif eventName == "CO_HOSTED_SITE_DOMAIN" and self.opts["cohosted"]:
            countryNames.append(self.detectCountryFromDomainName(eventData))
        elif eventName == "SIMILARDOMAIN" and self.opts["similardomain"]:
            countryNames.append(self.detectCountryFromDomainName(eventData))
        elif eventName == "IBAN_NUMBER":
            countryNames.append(self.detectCountryFromIBAN(eventData))
        elif eventName in ["DOMAIN_WHOIS", "GEOINFO", "PHYSICAL_ADDRESS"]:
            countryNames.extend(self.detectCountryFromData(eventData))
        elif eventName == "AFFILIATE_DOMAIN_WHOIS" and self.opts["affiliate"]:
            countryNames.extend(self.detectCountryFromData(eventData))
        elif eventName == "CO_HOSTED_SITE_DOMAIN_WHOIS" and self.opts["cohosted"]:
            countryNames.extend(self.detectCountryFromData(eventData))

        if not countryNames:
            self.debug(f"Found no country names associated with {eventName}: {eventData}")
            return

        for countryName in set(countryNames):
            if not countryName:
                continue

            self.debug(f"Found country name: {countryName}")

            evt = SpiderFootEvent("COUNTRY_NAME", countryName, self.__name__, event)
            evt.moduleDataSource = moduleDataSource
            self.notifyListeners(evt)

# End of sfp_countryname class
