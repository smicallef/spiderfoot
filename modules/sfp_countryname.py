# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_countryname
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_iban, sfp_phone, sfp_whois) and identifying country names
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     28/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import phonenumbers
from phonenumbers.phonenumberutil import region_code_for_country_code

class sfp_countryname(SpiderFootPlugin):
    """Country Name Extractor:Footprint,Investigate,Passive:Content Analysis::Identify country names in any obtained data."""

    # Default options
    opts = {
        # options specific to this module
        'cohosted' : True,
        'affiliate' : True,
        'noncountrytld' : True,
        'noncountrytlddefault' : "United States",
        'similardomain' : False,
    }

    # Option descriptions
    optdescs = {
        'cohosted' : "Obtain country name from co-hosted sites",
        'affiliate' : "Obtain country name from affiliate sites",
        'noncountrytld' : "Parse TLDs not associated with any country as default country domains",
        'noncountrytlddefault' : "Default country name for TLDs not associated with any country(.com, .net, .org, .gov, .mil)",
        'similardomain' : "Obtain country name from similar domains"
    }

    results = None
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Getter method for country codes and country names dictionary
    def getCountryCodeDict(self):

        # Dictionary of country codes and country names
        abbvCountryCodes = {
            "AF" : "Afghanistan", "AX" : "Aland Islands", "AL" : "Albania",
            "DZ" : "Algeria", "AS" : "American Samoa", "AD" : "Andorra",
            "AO" : "Angola", "AI" : "Anguilla", "AQ" : "Antarctica",
            "AG" : "Antigua and Barbuda", "AR" : "Argentina", "AM" : "Armenia",
            "AW" : "Aruba", "AU" : "Australia", "AT" : "Austria",
            "AZ" : "Azerbaijan", "BS" : "Bahamas", "BH" : "Bahrain",
            "BD" : "Bangladesh", "BB" : "Barbados", "BY" : "Belarus",
            "BE" : "Belgium", "BZ" : "Belize", "BJ" : "Benin",
            "BM" : "Bermuda", "BT" : "Bhutan", "BO" : "Bolivia",
            "BQ" : "Bonaire, Saint Eustatius and Saba", "BA" : "Bosnia and Herzegovina", "BW" : "Botswana",
            "BV" : "Bouvet Island", "BR" : "Brazil", "IO" : "British Indian Ocean Territory",
            "VG" : "British Virgin Islands", "BN" : "Brunei", "BG" : "Bulgaria",
            "BF" : "Burkina Faso", "BI" : "Burundi", "KH" : "Cambodia",
            "CM" : "Cameroon", "CA" : "Canada", "CV" : "Cape Verde",
            "KY" : "Cayman Islands", "CF" : "Central African Republic", "TD" : "Chad",
            "CL" : "Chile", "CN" : "China", "CX" : "Christmas Island",
            "CC" : "Cocos Islands", "CO" : "Colombia", "KM" : "Comoros",
            "CK" : "Cook Islands", "CR" : "Costa Rica", "HR" : "Croatia",
            "CU" : "Cuba", "CW" : "Curacao", "CY" : "Cyprus",
            "CZ" : "Czech Republic", "CD" : "Democratic Republic of the Congo", "DK" : "Denmark",
            "DJ" : "Djibouti", "DM" : "Dominica", "DO" : "Dominican Republic",
            "TL" : "East Timor", "EC" : "Ecuador", "EG" : "Egypt",
            "SV" : "El Salvador", "GQ" : "Equatorial Guinea", "ER" : "Eritrea",
            "EE" : "Estonia", "ET" : "Ethiopia", "FK" : "Falkland Islands",
            "FO" : "Faroe Islands", "FJ" : "Fiji", "FI" : "Finland",
            "FR" : "France", "GF" : "French Guiana", "PF" : "French Polynesia",
            "TF" : "French Southern Territories", "GA" : "Gabon", "GM" : "Gambia",
            "GE" : "Georgia", "DE" : "Germany", "GH" : "Ghana",
            "GI" : "Gibraltar", "GR" : "Greece", "GL" : "Greenland",
            "GD" : "Grenada", "GP" : "Guadeloupe", "GU" : "Guam",
            "GT" : "Guatemala", "GG" : "Guernsey", "GN" : "Guinea",
            "GW" : "Guinea-Bissau", "GY" : "Guyana", "HT" : "Haiti",
            "HM" : "Heard Island and McDonald Islands", "HN" : "Honduras", "HK" : "Hong Kong",
            "HU" : "Hungary", "IS" : "Iceland", "IN" : "India",
            "ID" : "Indonesia", "IR" : "Iran", "IQ" : "Iraq",
            "IE" : "Ireland", "IM" : "Isle of Man", "IL" : "Israel",
            "IT" : "Italy", "CI" : "Ivory Coast", "JM" : "Jamaica",
            "JP" : "Japan", "JE" : "Jersey", "JO" : "Jordan",
            "KZ" : "Kazakhstan", "KE" : "Kenya", "KI" : "Kiribati",
            "XK" : "Kosovo", "KW" : "Kuwait", "KG" : "Kyrgyzstan",
            "LA" : "Laos", "LV" : "Latvia", "LB" : "Lebanon",
            "LS" : "Lesotho", "LR" : "Liberia", "LY" : "Libya",
            "LI" : "Liechtenstein", "LT" : "Lithuania", "LU" : "Luxembourg",
            "MO" : "Macao", "MK" : "Macedonia", "MG" : "Madagascar",
            "MW" : "Malawi", "MY" : "Malaysia", "MV" : "Maldives",
            "ML" : "Mali", "MT" : "Malta", "MH" : "Marshall Islands",
            "MQ" : "Martinique", "MR" : "Mauritania", "MU" : "Mauritius",
            "YT" : "Mayotte", "MX" : "Mexico", "FM" : "Micronesia",
            "MD" : "Moldova", "MC" : "Monaco", "MN" : "Mongolia",
            "ME" : "Montenegro", "MS" : "Montserrat", "MA" : "Morocco",
            "MZ" : "Mozambique", "MM" : "Myanmar", "NA" : "Namibia",
            "NR" : "Nauru", "NP" : "Nepal", "NL" : "Netherlands",
            "AN" : "Netherlands Antilles", "NC" : "New Caledonia", "NZ" : "New Zealand",
            "NI" : "Nicaragua", "NE" : "Niger", "NG" : "Nigeria",
            "NU" : "Niue", "NF" : "Norfolk Island", "KP" : "North Korea",
            "MP" : "Northern Mariana Islands", "NO" : "Norway", "OM" : "Oman",
            "PK" : "Pakistan", "PW" : "Palau", "PS" : "Palestinian Territory",
            "PA" : "Panama", "PG" : "Papua New Guinea", "PY" : "Paraguay",
            "PE" : "Peru", "PH" : "Philippines", "PN" : "Pitcairn",
            "PL" : "Poland", "PT" : "Portugal", "PR" : "Puerto Rico",
            "QA" : "Qatar", "CG" : "Republic of the Congo", "RE" : "Reunion",
            "RO" : "Romania", "RU" : "Russia", "RW" : "Rwanda",
            "BL" : "Saint Barthelemy", "SH" : "Saint Helena", "KN" : "Saint Kitts and Nevis",
            "LC" : "Saint Lucia", "MF" : "Saint Martin", "PM" : "Saint Pierre and Miquelon",
            "VC" : "Saint Vincent and the Grenadines", "WS" : "Samoa", "SM" : "San Marino",
            "ST" : "Sao Tome and Principe", "SA" : "Saudi Arabia", "SN" : "Senegal",
            "RS" : "Serbia", "CS" : "Serbia and Montenegro", "SC" : "Seychelles",
            "SL" : "Sierra Leone", "SG" : "Singapore", "SX" : "Sint Maarten",
            "SK" : "Slovakia", "SI" : "Slovenia", "SB" : "Solomon Islands",
            "SO" : "Somalia", "ZA" : "South Africa", "GS" : "South Georgia and the South Sandwich Islands",
            "KR" : "South Korea", "SS" : "South Sudan", "ES" : "Spain",
            "LK" : "Sri Lanka", "SD" : "Sudan", "SR" : "Suriname",
            "SJ" : "Svalbard and Jan Mayen", "SZ" : "Swaziland", "SE" : "Sweden",
            "CH" : "Switzerland", "SY" : "Syria", "TW" : "Taiwan",
            "TJ" : "Tajikistan", "TZ" : "Tanzania", "TH" : "Thailand",
            "TG" : "Togo", "TK" : "Tokelau", "TO" : "Tonga",
            "TT" : "Trinidad and Tobago", "TN" : "Tunisia", "TR" : "Turkey",
            "TM" : "Turkmenistan", "TC" : "Turks and Caicos Islands", "TV" : "Tuvalu",
            "VI" : "U.S. Virgin Islands", "UG" : "Uganda", "UA" : "Ukraine",
            "AE" : "United Arab Emirates", "GB" : "United Kingdom", "US" : "United States",
            "UM" : "United States Minor Outlying Islands", "UY" : "Uruguay", "UZ" : "Uzbekistan",
            "VU" : "Vanuatu", "VA" : "Vatican", "VE" : "Venezuela",
            "VN" : "Vietnam", "WF" : "Wallis and Futuna", "EH" : "Western Sahara",
            "YE" : "Yemen", "ZM" : "Zambia", "ZW" : "Zimbabwe", 
            # Below are not country codes but recognized as TLDs
            "AC" : "Ascension Island", "EU" : "European Union", "SU" : "Soviet Union", 
            "UK" : "United Kingdom"
        }
        return abbvCountryCodes
    
    # Getter method for dictionary of codes not associated with any country
    def getNonCountryCodesDict(self):
        
        # List of TLD not associated with any country
        nonCountryCodes = ["COM", "NET", "ORG", "GOV", "MIL"]

        # Get default country code set from opts dictionary
        defaultCountryCode = self.opts["noncountrytlddefault"]

        nonCountryCodesDict = dict()

        # Set default country name for all keys
        for nonCountryCode in nonCountryCodes: 
            nonCountryCodesDict[nonCountryCode] = defaultCountryCode
        
        return nonCountryCodesDict
    
    # Detect name of country from phone number 
    def detectCountryFromPhone(self, srcPhoneNumber):

        # Get dictionary of country codes and country names
        abbvCountryCodes = self.getCountryCodeDict()

        # Check if country code is present in the phone number
        try:
            # Parse source phone nummber
            phoneNumber = phonenumbers.parse(srcPhoneNumber)
            # Get country code of phone number
            countryCode = region_code_for_country_code(phoneNumber.country_code)
            # try block handles key not found exception
            return abbvCountryCodes[countryCode.upper()]
        except:
            # Region code not present in source phone number
            self.sf.debug("Skipped invalid phone number: " + srcPhoneNumber)
            return None

    
    # Detect name of country from TLD of domain name
    def detectCountryFromTLD(self, srcDomain):
        
        # Get dictionary of TLD country codes and country names
        tldCountryCodes = self.getCountryCodeDict()
        
        # Get dictionary of non country TLD codes
        tldNonCountryCodes = self.getNonCountryCodesDict()

        # Split domain into parts by '.' 
        # Country TLDs are reserved 
        domainParts = srcDomain.split(".")

        # Search for country TLD in the domain parts - reversed
        for part in domainParts[::-1]:
            if part.upper() in tldCountryCodes.keys():
                return tldCountryCodes[part.upper()]

        # Search for non country TLD in the domain parts
        for part in domainParts[::-1]:
            if part.upper() in tldNonCountryCodes.keys():
                return tldNonCountryCodes[part.upper()]

        # No associated country name is found
        return None

    # Detect name of country from IBAN
    def detectCountryFromIBAN(self, srcIBAN):

        # Get dictionary of country codes and country names
        tldCountryCodes = self.getCountryCodeDict()
        try:
            # Get country code from IBAN 
            countryCode = srcIBAN[0:2].upper()
            return tldCountryCodes[countryCode]
        except:
            # No country name is found in the IBAN
            return None
    
    # Detect name of country from whois lookup, Geo Info, Physical Address data
    def detectCountryFromData(self, srcData):
        
        # Get dictionary of country codes and  country names
        abbvCountryCodes = self.getCountryCodeDict()
        countries = list()

        # Look for countrycodes and country in source data
        for countryName in abbvCountryCodes.values(): 

            # Look for country name in source data
            # Spaces are not included since New Jersey and others
            # will get interpreted as Jersey, etc.
            matchCountries = re.findall("[,'\"\:\=\[\(\[\n\t\r\.] ?" + countryName + "[,'\"\:\=\[\(\[\n\t\r\.]", srcData, re.IGNORECASE)

            if len(matchCountries) > 0:
                # Get country name from first index of list
                # Extract only the text part of the country code
                matchCountry = matchCountries[0].strip(",").strip("'").strip("\"").strip()
                countries.append(matchCountry)

            if len(matchCountries) > 0:
                # Get country name from first index of list
                # Extract only the text part of the country code
                matchCountry = matchCountries[0].strip(",").strip("'").strip("\"").strip()
                countries.append(matchCountry)

        # Look for "Country: ", usually found in Whois records
        matchCountries = re.findall("country: (.*)", srcData, re.IGNORECASE)
        if matchCountries:
            for m in matchCountries:
                m = m.strip()
                if m in abbvCountryCodes:
                    countries.append(abbvCountryCodes[m])
                if m in abbvCountryCodes.values():
                    countries.append(m)

        # If any countries are found
        if len(countries) > 0:
            return countries

        return None
            
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
        
        evttype = "COUNTRY_NAME"

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Generate event data hash
        eventDataHash = self.sf.hashstring(eventData)
        # Do not parse duplicate incoming data
        if eventDataHash in self.results:
            self.sf.debug("Already found from this source")
            return None 
        
        self.results[eventDataHash] = True

        countryNames = list()

        # Process the event data based on incoming event type
        if eventName == "PHONE_NUMBER":
            countryNames.append(self.detectCountryFromPhone(eventData))
        elif eventName == "DOMAIN_NAME" or (eventName == "AFFILIATE_DOMAIN_NAME" and self.opts["affiliate"]) or(eventName == "CO_HOSTED_SITE_DOMAIN" and self.opts["cohosted"]) or  (eventName == "SIMILARDOMAIN" and self.opts["similardomain"]):
            countryNames.append(self.detectCountryFromTLD(eventData))
        elif eventName == "IBAN_NUMBER":
            countryNames.append(self.detectCountryFromIBAN(eventData))
        elif eventName in ["DOMAIN_WHOIS", "GEOINFO", "PHYSICAL_ADDRESS"] or (eventName == "AFFILIATE_DOMAIN_WHOIS" and self.opts["affiliate"]) or (eventName == "CO_HOSTED_SITE_DOMAIN_WHOIS" and self.opts["cohosted"]):
            tempDataList =  self.detectCountryFromData(eventData)
            if tempDataList is None:
                countryNames.append(None)
            else:
                countryNames.extend(tempDataList)
        
        # Check if countryNames is empty
        if len(countryNames) == 0:
            return None

        # Convert list to set to remove duplicates
        countryNames = set(countryNames)

        for countryName in countryNames:
            if countryName == '' or countryName == None:
                continue
            self.sf.debug("Found country name: " + countryName)

            evt = SpiderFootEvent(evttype, countryName, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)
        return None
        
# End of sfp_countryname class
