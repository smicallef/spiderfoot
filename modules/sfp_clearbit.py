# -------------------------------------------------------------------------------
# Name:         sfp_clearbit
# Purpose:      Query clearbit.com using their API.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/03/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_clearbit(SpiderFootPlugin):

    meta = {
        'name': "Clearbit",
        'summary': "Check for names, addresses, domains and more based on lookups of e-mail addresses on clearbit.com.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://clearbit.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://clearbit.com/docs"
            ],
            'apiKeyInstructions': [
                "Visit https://clearbit.com",
                "Register account for a Free Trial",
                "Navigate to https://dashboard.clearbit.com/api",
                "The API key is listed under 'Your API Key'"
            ],
            'favIcon': "https://clearbit.com/assets/site/logo.png",
            'logo': "https://clearbit.com/assets/site/logo.png",
            'description': "Clearbit is the marketing data engine for all of your customer interactions. "
            "Deeply understand your customers, identify future prospects, "
            "and personalize every single marketing and sales interaction.\n"
            "Rely on fresh, accurate data with our proprietary real-time lookups. "
            "Then act on new information immediately, with sales alerting and job change notifications.\n"
            "Get company attributes like employee count, technologies used, and industry classification—and "
            "get employee details like role, seniority, and even job change notifications, right at your fingertips.\n"
            "With our dataset and machine learning algorithms, you’ll have all of "
            "the information you need to convert leads and grow your business.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Clearbit.com API key."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "PHONE_NUMBER", "PHYSICAL_ADDRESS",
                "AFFILIATE_INTERNET_NAME", "EMAILADDR", "EMAILADDR_GENERIC"]

    def query(self, t):
        api_key = self.opts['api_key']
        if type(api_key) == str:
            api_key = api_key.encode('utf-8')
        url = "https://person.clearbit.com/v2/combined/find?email=" + t
        token = base64.b64encode(api_key + ':'.encode('utf-8'))
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + token.decode('utf-8')
        }

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot", headers=headers)

        if res['code'] != "200":
            self.error("Return code indicates no results or potential API key failure or exceeded limits.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from clearbit.io: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_clearbit but did not set an API key!")
            self.errorState = True
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)
        if not data:
            return

        try:
            # Get the name associated with the e-mail
            if "person" in data:
                name = data['person']['name']['fullName']
                evt = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + name,
                                      self.__name__, event)
                self.notifyListeners(evt)
        except Exception:
            self.debug("Unable to extract name from JSON.")
            pass

        # Get the location of the person, also indicating
        # the location of the employer.
        try:
            if "geo" in data:
                loc = ""

                if 'streetNumber' in data['geo']:
                    loc += data['geo']['streetNumber'] + ", "
                if 'streetName' in data['geo']:
                    loc += data['geo']['streetName'] + ", "
                if 'city' in data['geo']:
                    loc += data['geo']['city'] + ", "
                if 'postalCode' in data['geo']:
                    loc += data['geo']['postalCode'] + ", "
                if 'state' in data['geo']:
                    loc += data['geo']['state'] + ", "
                if 'country' in data['geo']:
                    loc += data['geo']['country']
                evt = SpiderFootEvent("PHYSICAL_ADDRESS", loc, self.__name__, event)
                self.notifyListeners(evt)
        except Exception:
            self.debug("Unable to extract location from JSON.")
            pass

        try:
            if "company" in data:
                if 'domainAliases' in data['company']:
                    for d in data['company']['domainAliases']:
                        evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME", d,
                                              self.__name__, event)
                        self.notifyListeners(evt)

                if 'site' in data['company']:
                    if 'phoneNumbers' in data['company']['site']:
                        for p in data['company']['site']['phoneNumbers']:
                            evt = SpiderFootEvent("PHONE_NUMBER", p, self.__name__, event)
                            self.notifyListeners(evt)
                    if 'emailAddresses' in data['company']['site']:
                        for e in data['company']['site']['emailAddresses']:
                            if e.split("@")[0] in self.opts['_genericusers'].split(","):
                                evttype = "EMAILADDR_GENERIC"
                            else:
                                evttype = "EMAILADDR"
                            evt = SpiderFootEvent(evttype, e, self.__name__, event)
                            self.notifyListeners(evt)

                # Get the location of the person, also indicating
                # the location of the employer.
                if 'geo' in data['company']:
                    loc = ""

                    if 'streetNumber' in data['company']['geo']:
                        loc += data['company']['geo']['streetNumber'] + ", "
                    if 'streetName' in data['company']['geo']:
                        loc += data['company']['geo']['streetName'] + ", "
                    if 'city' in data['company']['geo']:
                        loc += data['company']['geo']['city'] + ", "
                    if 'postalCode' in data['company']['geo']:
                        loc += data['company']['geo']['postalCode'] + ", "
                    if 'state' in data['company']['geo']:
                        loc += data['company']['geo']['state'] + ", "
                    if 'country' in data['company']['geo']:
                        loc += data['company']['geo']['country']
                    evt = SpiderFootEvent("PHYSICAL_ADDRESS", loc, self.__name__, event)
                    self.notifyListeners(evt)
        except Exception:
            self.debug("Unable to company info from JSON.")
            pass

# End of sfp_clearbit class
