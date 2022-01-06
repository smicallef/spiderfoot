# -------------------------------------------------------------------------------
# Name:         sfp_haveibeenpwned
# Purpose:      Query haveibeenpwned.com to see if an e-mail account has been hacked.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/02/2015
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_haveibeenpwned(SpiderFootPlugin):

    meta = {
        'name': "HaveIBeenPwned",
        'summary': "Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://haveibeenpwned.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://haveibeenpwned.com/API/v3",
                "https://haveibeenpwned.com/FAQs"
            ],
            'apiKeyInstructions': [
                "Visit https://haveibeenpwned.com/API/Key",
                "Register an account",
                "Visit https://haveibeenpwned.com/API/Key",
            ],
            'favIcon': "https://haveibeenpwned.com/favicon.ico",
            'logo': "https://haveibeenpwned.com/favicon.ico",
            'description': "Check if you have an account that has been compromised in a data breach.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "HaveIBeenPwned.com API key."
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
        return ["EMAILADDR", "PHONE_NUMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED", "PHONE_NUMBER_COMPROMISED", "LEAKSITE_CONTENT", "LEAKSITE_URL"]

    def query(self, qry):
        if self.opts['api_key']:
            version = "3"
        else:
            version = "2"

        url = f"https://haveibeenpwned.com/api/v{version}/breachedaccount/{qry}"
        hdrs = {"Accept": f"application/vnd.haveibeenpwned.v{version}+json"}
        retry = 0

        if self.opts['api_key']:
            hdrs['hibp-api-key'] = self.opts['api_key']

        while retry < 2:
            # https://haveibeenpwned.com/API/v2#RateLimiting
            time.sleep(1.5)
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent="SpiderFoot", headers=hdrs)

            if res['code'] == "200":
                break

            if res['code'] == "404":
                return None

            if res['code'] == "429":
                # Back off a little further
                time.sleep(2)
            retry += 1

            if res['code'] == "401":
                self.error("Failed to authenticate key with HaveIBeenPwned.com.")
                self.errorState = True
                return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from HaveIBeenPwned?: {e}")

        return None

    def queryPaste(self, qry):
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{qry}"
        headers = {
            'Accept': "application/json",
            'hibp-api-key': self.opts['api_key']
        }

        retry = 0

        while retry < 2:
            # https://haveibeenpwned.com/API/v2#RateLimiting
            time.sleep(1.5)
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent="SpiderFoot", headers=headers)

            if res['code'] == "200":
                break

            if res['code'] == "404":
                return None

            if res['code'] == "429":
                # Back off a little further
                time.sleep(2)
            retry += 1

            if res['code'] == "401":
                self.error("Failed to authenticate key with HaveIBeenPwned.com.")
                self.errorState = True
                return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from HaveIBeenPwned?: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_haveibeenpwned but did not set an API key!")
            self.errorState = True
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)
        if data is not None:
            for n in data:
                try:
                    site = n["Name"]
                except Exception as e:
                    self.debug(f"Unable to parse result from HaveIBeenPwned?: {e}")
                    continue

                # Notify other modules of what you've found
                if eventName == 'EMAILADDR':
                    e = SpiderFootEvent("EMAILADDR_COMPROMISED", eventData + " [" + site + "]",
                                        self.__name__, event)
                else:
                    e = SpiderFootEvent("PHONE_NUMBER_COMPROMISED", eventData + " [" + site + "]",
                                        self.__name__, event)
                self.notifyListeners(e)

        # This API endpoint doesn't support phone numbers
        if eventName == "PHONE_NUMBER":
            return
        pasteData = self.queryPaste(eventData)
        if pasteData is None:
            return

        sites = {
            "Pastebin": "https://pastebin.com/",
            "Pastie": "http://pastie.org/p/",
            "Slexy": "https://slexy.org/view/",
            "Ghostbin": "https://ghostbin.com/paste/",
            "JustPaste": "https://justpaste.it/",
        }
        links = set()
        for n in pasteData:
            try:
                source = n.get("Source")
                site = source
                if source in sites:
                    site = f"{sites[n.get('Source')]}{n.get('Id')}"
                    links.add(site)

            except Exception as e:
                self.debug(f"Unable to parse result from HaveIBeenPwned?: {e}")
                continue

        for link in links:
            try:
                self.debug("Found a link: " + link)

                if self.checkForStop():
                    return

                res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.debug(f"Ignoring {link} as no data returned")
                    continue

                if re.search(r"[^a-zA-Z\-\_0-9]" + re.escape(eventData) + r"[^a-zA-Z\-\_0-9]", res['content'], re.IGNORECASE) is None:
                    continue

                evt1 = SpiderFootEvent("LEAKSITE_URL", link, self.__name__, event)
                self.notifyListeners(evt1)

                evt2 = SpiderFootEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt1)
                self.notifyListeners(evt2)

            except Exception as e:
                self.debug(f"Unable to parse result from HaveIBeenPwned?: {e}")
                continue

# End of sfp_haveibeenpwned class
