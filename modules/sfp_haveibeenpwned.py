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
            'apiKeyInstructions': [],
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
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED", "LEAKSITE_CONTENT", "LEAKSITE_URL"]

    def query(self, qry):
        ret = None
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
                self.sf.error("Failed to authenticate key with HaveIBeenPwned.com.")
                self.errorState = True
                return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from HaveIBeenPwned?: {e}")
            return None

        return ret

    def queryPaste(self, qry):
        ret = None

        if not self.opts['api_key']:
            return None

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
                self.sf.error("Failed to authenticate key with HaveIBeenPwned.com.")
                self.errorState = True
                return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from HaveIBeenPwned?: {e}")
            return None

        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            self.results[eventData] = True

        data = self.query(eventData)
        if data is not None:
            for n in data:
                try:
                    if not self.opts['api_key']:
                        site = n["Title"]
                    else:
                        site = n["Name"]
                except Exception as e:
                    self.sf.debug(f"Unable to parse result from HaveIBeenPwned?: {e}")
                    continue

                evt = eventName + "_COMPROMISED"
                # Notify other modules of what you've found
                e = SpiderFootEvent(evt, eventData + " [" + site + "]",
                                    self.__name__, event)
                self.notifyListeners(e)

        pasteData = self.queryPaste(eventData)
        if pasteData is None:
            return None

        sites = {
            "Pastebin": "https://pastebin.com/",
            "Pastie": "http://pastie.org/",
            "Slexy": "https://slexy.org/",
            "Ghostbin": "https://ghostbin.com/",
            "QuickLeak": "http://www.quickleak.net/",
            "JustPaste": "https://justpaste.it/",
        }

        for n in pasteData:
            try:
                source = n.get("Source")
                site = source
                if source in sites.keys():
                    site = sites[n.get("Source")]

                if not n.get("Source") is None:
                    e = SpiderFootEvent("LEAKSITE_URL", site, self.__name__, event)
                    self.notifyListeners(e)

                if not n.get("Title") is None:
                    e = SpiderFootEvent("LEAKSITE_CONTENT", n.get("Title"), self.__name__, event)
                    self.notifyListeners(e)

            except Exception as e:
                self.sf.debug(f"Unable to parse result from HaveIBeenPwned?: {e}")
                continue


# End of sfp_haveibeenpwned class
