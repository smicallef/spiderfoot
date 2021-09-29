# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_jsonwhoiscom
# Purpose:     Search JsonWHOIS.com for WHOIS records associated with a domain.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-06-20
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_jsonwhoiscom(SpiderFootPlugin):

    meta = {
        'name': "JsonWHOIS.com",
        'summary': "Search JsonWHOIS.com for WHOIS records associated with a domain.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://jsonwhois.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://jsonwhois.com/docs"
            ],
            'apiKeyInstructions': [
                "Visit https://jsonwhois.com",
                "Sign up for a free account",
                "Navigate to https://jsonwhois.com/dashboard",
                "The API key is listed under 'Api Key'"
            ],
            'favIcon': "https://jsonwhois.com/assets/fav.ico",
            'logo': "https://jsonwhois.com/assets/fav.ico",
            'description': "Get access to accurate Whois records for generic and country TLDs. "
            "Around 1000 gTLDs include .com, .org, .net, .us, .biz, .info, .mobi, .pro, .asia and many other new ones.\n"
            "Raw and parsed Whois data are both accessible for downloads in the form of "
            "MYSQL or MYSQL database dumps and Comma Separated Values (.CSV) files.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "delay": 1,
    }

    # Option descriptions
    optdescs = {
        "api_key": "JsonWHOIS.com API key.",
        "delay": "Delay between requests, in seconds.",
    }

    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "AFFILIATE_DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "DOMAIN_REGISTRAR", "DOMAIN_WHOIS", "PROVIDER_DNS",
                "EMAILADDR", "EMAILADDR_GENERIC", "PHONE_NUMBER", "PHYSICAL_ADDRESS",
                "AFFILIATE_DOMAIN_UNREGISTERED"]

    # Query domain
    # https://jsonwhois.com/docs
    def queryDomain(self, qry):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept": "application/json",
            "Authorization": "Token token=" + self.opts["api_key"]
        }

        res = self.sf.fetchUrl(
            f"https://jsonwhois.com/api/v1/whois?{urllib.parse.urlencode(params)}",
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    def parseAPIResponse(self, res):
        if res['code'] == '404':
            self.debug("No results for query")
            return None

        # Sometimes JsonWHOIS.com returns HTTP 500 errors rather than 404
        if res['code'] == '500' and res['content'] == '{"error":"Call failed"}':
            self.debug("No results for query")
            return None

        if res['code'] == "401":
            self.error("Invalid JsonWHOIS.com API key.")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by JsonWHOIS.com")
            self.errorState = True
            return None

        if res['code'] == '503':
            self.error("JsonWHOIS.com service unavailable")
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from JsonWHOIS.com")
            self.errorState = True
            return None

        if res['content'] is None:
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

        if self.errorState:
            return

        if eventData in self.results:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_jsonwhoiscom but did not set an API key!")
            self.errorState = True
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        res = self.queryDomain(eventData)

        if res is None:
            self.debug(f"No information found for domain {eventData}")
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', str(res), self.__name__, event)
        self.notifyListeners(evt)

        dns_providers = list()

        nameservers = res.get('nameservers')
        if nameservers:
            for nameserver in nameservers:
                if nameserver:
                    nameserver_name = nameserver.get('name')
                    if nameserver_name:
                        dns_providers.append(nameserver_name)

        contacts = list()

        registrant_contacts = res.get('registrant_contacts')
        if registrant_contacts:
            for contact in registrant_contacts:
                contacts.append(contact)

        admin_contacts = res.get('admin_contacts')
        if admin_contacts:
            for contact in admin_contacts:
                contacts.append(contact)

        technical_contacts = res.get('technical_contacts')
        if technical_contacts:
            for contact in technical_contacts:
                contacts.append(contact)

        emails = list()
        names = list()
        phones = list()
        locations = list()

        for contact in contacts:
            email = contact.get('email')
            if email:
                if self.sf.validEmail(email):
                    emails.append(email)

            name = contact.get("name")
            if name:
                names.append(name)

            phone = contact.get('phone')
            if phone:
                phone = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").replace(".", "")
                phones.append(phone)

            country = self.sf.countryNameFromCountryCode(contact.get('country_code'))
            location = ', '.join([_f for _f in [contact.get('address'), contact.get('city'), contact.get('state'), contact.get('zip'), country] if _f])
            if location:
                locations.append(location)

        for email in set(emails):
            mail_domain = email.lower().split('@')[1]
            if self.getTarget().matches(mail_domain, includeChildren=True):
                if email.split("@")[0] in self.opts['_genericusers'].split(","):
                    evttype = "EMAILADDR_GENERIC"
                else:
                    evttype = "EMAILADR"
                evt = SpiderFootEvent(evttype, email, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("AFFILIATE_EMAILADDR", email, self.__name__, event)
                self.notifyListeners(evt)

        if eventName in ["DOMAIN_NAME"]:
            raw = res.get('raw')
            if raw:
                evt = SpiderFootEvent("DOMAIN_WHOIS", raw, self.__name__, event)
                self.notifyListeners(evt)

            registrar = res.get("registrar")
            if registrar:
                registrar_name = registrar.get("name")
                if registrar_name:
                    evt = SpiderFootEvent("DOMAIN_REGISTRAR", registrar_name, self.__name__, event)
                    self.notifyListeners(evt)

            for dns_provider in set(dns_providers):
                evt = SpiderFootEvent("PROVIDER_DNS", dns_provider, self.__name__, event)
                self.notifyListeners(evt)

            for name in set(names):
                evt = SpiderFootEvent("RAW_RIR_DATA", f"Possible full name {name}", self.__name__, event)
                self.notifyListeners(evt)

            for phone in set(phones):
                evt = SpiderFootEvent("PHONE_NUMBER", phone, self.__name__, event)
                self.notifyListeners(evt)

            for location in set(locations):
                evt = SpiderFootEvent("PHYSICAL_ADDRESS", location, self.__name__, event)
                self.notifyListeners(evt)

        if eventName in ["AFFILIATE_DOMAIN_NAME"]:
            raw = res.get('raw')
            if raw:
                evt = SpiderFootEvent("AFFILIATE_DOMAIN_WHOIS", raw, self.__name__, event)
                self.notifyListeners(evt)

            available = res.get('available?')
            if available:
                evt = SpiderFootEvent("AFFILIATE_DOMAIN_UNREGISTERED", eventData, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_jsonwhoiscom class
