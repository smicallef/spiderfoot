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
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_jsonwhoiscom(SpiderFootPlugin):
    """JsonWHOIS.com:Footprint,Investigate,Passive:Search Engines:apikey:Search JsonWHOIS.com for WHOIS records associated with a domain."""

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
                "HUMAN_NAME", "AFFILIATE_DOMAIN_UNREGISTERED"]

    # Query domain
    # https://jsonwhois.com/docs
    def queryDomain(self, qry):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            "Accept" : "application/json",
            "Authorization" : "Token token=" + self.opts["api_key"]
        }
        
        res = self.sf.fetchUrl(
          "https://jsonwhois.com/api/v1/whois?%s" % urllib.parse.urlencode(params),
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

        # Sometimes JsonWHOIS.com returns HTTP 500 errors rather than 404
        if res['code'] == '500' and res['content'] == '{"error":"Call failed"}':
            self.sf.debug("No results for query")
            return None

        if res['code'] == "401":
            self.sf.error("Invalid JsonWHOIS.com API key.", False)
            self.errorState = True
            return None

        if res['code'] == '429':
            self.sf.error("You are being rate-limited by JsonWHOIS.com", False)
            self.errorState = True
            return None

        if res['code'] == '503':
            self.sf.error("JsonWHOIS.com service unavailable", False)
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from JsonWHOIS.com", False)
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
            self.sf.error("You enabled sfp_jsonwhoiscom but did not set an API key!", False)
            self.errorState = True
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        res = self.queryDomain(eventData)

        if res is None:
            self.sf.debug("No information found for domain %s" % eventData)
            return None

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

            location = ', '.join([_f for _f in [contact.get('address'), contact.get('city'), contact.get('state'), contact.get('zip'), contact.get('country_code')] if _f])
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
                evt = SpiderFootEvent("HUMAN_NAME", name, self.__name__, event)
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
