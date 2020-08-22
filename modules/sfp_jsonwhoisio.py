# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_jsonwhoisio
# Purpose:     Search JsonWHOIS.io for WHOIS records associated with a domain.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-06-20
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_jsonwhoisio(SpiderFootPlugin):
    """JsonWHOIS.io:Footprint,Investigate,Passive:Search Engines:apikey:Search JsonWHOIS.io for WHOIS records associated with a domain."""

    meta = {
        'name': "JsonWHOIS.io",
        'summary': "Search JsonWHOIS.io for WHOIS records associated with a domain.",
        'flags': [ "apikey" ],
        'useCases': [ "Footprint", "Investigate", "Passive" ],
        'categories': [ "Search Engines" ]
    }

    # Default options
    opts = {
        "api_key": "",
        "delay": 1,
    }

    # Option descriptions
    optdescs = {
        "api_key": "JsonWHOIS.io API key.",
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
        return ["RAW_RIR_DATA", "DOMAIN_REGISTRAR", "PROVIDER_DNS",
                "EMAILADDR", "EMAILADDR_GENERIC", "PHONE_NUMBER", "PHYSICAL_ADDRESS",
                "HUMAN_NAME", "AFFILIATE_DOMAIN_UNREGISTERED"]

    def queryDomain(self, qry):
        """Query domain WHOIS
        https://jsonwhois.io/docs
        """
        params = {
            "key" : self.opts["api_key"],
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept" : "application/json",
        }
        
        res = self.sf.fetchUrl(
          "https://api.jsonwhois.io/whois/domain?%s" % urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def queryDomainAvailability(self, qry):
        """Query domain availability
        https://jsonwhois.io/docs
        """
        params = {
            "key" : self.opts["api_key"],
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept" : "application/json",
        }
        
        res = self.sf.fetchUrl(
          "https://api.jsonwhois.io/availability?%s" % urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    def parseAPIResponse(self, res):
        if res['code'] == '404':
            self.sf.debug("No results for query")
            return None

        if res['code'] == "401":
            self.sf.error("Invalid JsonWHOIS.io API key.", False)
            self.errorState = True
            return None

        if res['code'] == "402":
            self.sf.error("JsonWHOIS.io account billing issue.", False)
            self.errorState = True
            return None

        if res['code'] == '429':
            self.sf.error("You are being rate-limited by JsonWHOIS.io", False)
            self.errorState = True
            return None

        if res['code'] == '503':
            self.sf.error("JsonWHOIS.io service unavailable", False)
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from JsonWHOIS.io", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_jsonwhoisio but did not set an API key!", False)
            self.errorState = True
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventName == "AFFILIATE_DOMAIN_NAME":
            res = self.queryDomainAvailability(eventData)

            if res is None:
                self.sf.debug("No domain availability information found for domain %s" % eventData)
                return None

            evt = SpiderFootEvent('RAW_RIR_DATA', str(res), self.__name__, event)
            self.notifyListeners(evt)

            is_available = res.get('is_available')
            if is_available:
                evt = SpiderFootEvent("AFFILIATE_DOMAIN_UNREGISTERED", eventData, self.__name__, event)
                self.notifyListeners(evt)

        if eventName == "DOMAIN_NAME":
            res = self.queryDomain(eventData)

            if res is None:
                self.sf.debug("No domain WHOIS information found for domain %s" % eventData)
                return None

            res = res.get("result")
            if not res:
                self.sf.debug("No domain WHOIS information found for domain %s" % eventData)
                return None

            evt = SpiderFootEvent('RAW_RIR_DATA', str(res), self.__name__, event)
            self.notifyListeners(evt)

            registrar = res.get("registrar")
            if registrar:
                registrar_name = registrar.get("name")
                if registrar_name:
                    evt = SpiderFootEvent("DOMAIN_REGISTRAR", registrar_name, self.__name__, event)
                    self.notifyListeners(evt)

            dns_providers = list()

            nameservers = res.get('nameservers')
            if nameservers:
                for nameserver in nameservers:
                    dns_providers.append(nameserver)

            contacts = list()

            whois_contacts = res.get('contacts')
            if whois_contacts:
                for contact_type in ['owner', 'admin', 'tech']:
                    if whois_contacts.get(contact_type):
                        for contact in whois_contacts.get(contact_type):
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

                location = ', '.join([_f for _f in [contact.get('address'), contact.get('city'), contact.get('state'), contact.get('zipcode'), contact.get('country')] if _f])
                if location:
                    locations.append(location)

            for email in set(emails):
                mail_domain = email.lower().split('@')[1]
                if self.getTarget().matches(mail_domain, includeChildren=True):
                    if email.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"
                    evt = SpiderFootEvent(evttype, email, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent("AFFILIATE_EMAILADDR", email, self.__name__, event)
                    self.notifyListeners(evt)

            for dns_provider in set(dns_providers):
                evt = SpiderFootEvent("PROVIDER_DNS", dns_provider, self.__name__, event)
                self.notifyListeners(evt)

            for name in set(names):
                evt = SpiderFootEvent("HUMAN_NAME", name, self.__name__, event)
                self.notifyListeners(evt)

            for phone in set(phones):
                evt = SpiderFootEvent("PHONE_NUMBER", phone, self.__name__, event)
                self.notifyListeners(evt)

            for location in set(locations):
                evt = SpiderFootEvent("PHYSICAL_ADDRESS", location, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_jsonwhoisio class
