# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_countryname
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_iban, [placeholder]) and identifying country names
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     28/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import phonenumbers
from phonenumbers.phonenumberutil import region_code_for_country_code

class sfp_countryname(SpiderFootPlugin):
    """Country Name Extractor:Footprint,Investigate,Passive:Content Analysis::Identify country names in any obtained data."""

    # Default options
    opts = {
        # options specific to this module
        'coHosted' : True,
        'affiliate' : True,
        'nonCountryTLD' : True
    }

    # Option descriptions
    optdescs = {
        'coHosted' : "Include searching of country name from CO_HOSTED_* data sources",
        'affiliate' : "Include searching of country name from AFFILIATE_* data sources",
        'nonCountryTLD' : "Parse TLDs not associated with any country as default values"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        # Override datasource for sfp_countryname module
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]
    
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
            "YE" : "Yemen", "ZM" : "Zambia", "ZW" : "Zimbabwe", "AC" : "Ascension Island",
            "EU" : "European Union", "SU" : "Soviet Union", "UK" : "United Kingdom"
        }
        return abbvCountryCodes
    # Detect name of country from phone number 
    def detectCountryFromPhone(self, srcPhoneNumber):

        # Get dictionary of country codes and country names
        abbvCountryCodes = self.getCountryCodeDict()

        # Parse source phone nummber
        phoneNumber = phonenumbers.parse(srcPhoneNumber)
        # Check if country code is present in the phone number
        try:
            countryCode = countryCode = region_code_for_country_code(phoneNumber.country_code)
        except:
            # Region code not present in source phone number
            self.debug("Skipped invalid phone number: " + srcPhoneNumber)
            return None
        return abbvCountryCodes[countryCode]
    
    def detectCountryFromTLD(self, srcDomain):
        
        # Get dictionary of country codes and country names
        tldCountryCodes = self.getCountryCodeDict()
        
        # Split domain into parts by '.'
        # Here we know that country TLDs are reserved 
        domainParts = srcDomain.split(".")

        # Search for country TLD in the domain parts
        # Note : What if it's not associated to any country ? (Example : .com)
        for part in domainParts:
            if part in tldCountryCodes.keys():
                return tldCountryCodes[part]

        # No associated country name is found
        return None
    def detectCountryFromIBAN(self, srcIBAN):

        # Get dictionary of country codes and country names
        tldCountryCodes = self.getCountryCodeDict()
        try:
            return tldCountryCodes[srcIBAN[0:2]]
        except:
            return None

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IBAN_NUMBER", "PHONE_NUMBER", "AFFILIATE_DOMAIN_NAME",
                "CO_HOSTED_SITE_DOMAIN", "DOMAIN_NAME", "SIMILARDOMAIN",
                "AFFILIATE_DOMAIN_WHOIS", "CO_HOSTED_SITE_DOMAIN_WHOIS",
                'DOMAIN_WHOIS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["COUNTRY_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        myres = list()

        # Based on the type of incoming event, the functions will be called

        # Extract country based on the different incoming data sources
        if eventName == "PHONE_NUMBER":
            countryName = self.detectCountryFromPhone(eventData)
        elif eventName in ["DOMAIN_NAME", "SIMILARDOMAIN"]:
            countryName = self.detectCountryFromTLD(eventData)
        elif eventName == "IBAN_NUMBER":
            countryName = self.detectCountryFromIBAN(eventData)
        # countryName = ( extract country names from WHOIS )
        # etc ... parse all incoming data sources
    
        evttype = "COUNTRY_NAME"

        # Check if country name already exists in results
        # Note : Make modifications to check k-v instead of only v for duplicate
        # k-v as in incoming event and current generated country name
        if countryName in myres:
            self.sf.debug("Already found from this source")
            return None 
        
        # Check if there is any country name associated to the phone number
        if countryName is None:
            self.sf.debug("No associated country name found")
            return None

        self.sf.debug("Found country name : " + countryName)

        myres.append(countryName)

        evt = SpiderFootEvent(evttype, mail, self.__name__, event)
        if event.moduleDataSource:
            evt.moduleDataSource = event.moduleDataSource
        else:
            evt.moduleDataSource = "Unknown"
        self.notifyListeners(evt)

        return None

# End of sfp_countryname class
