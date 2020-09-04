# -------------------------------------------------------------------------------
# Name:         sfp_fullcontact
# Purpose:      Query fullcontact.com using their API.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/02/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_fullcontact(SpiderFootPlugin):

    meta = {
        'name': "FullContact",
        'summary': "Gather domain and e-mail information from fullcontact.com.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.fullcontact.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://dashboard.fullcontact.com/api-ref",
                "https://www.fullcontact.com/developer-portal/",
                "https://www.fullcontact.com/insights-bundles/",
                "https://dashboard.fullcontact.com/docs",
                "https://www.fullcontact.com/faq/"
            ],
            'apiKeyInstructions': [
                "Visit https://fullcontact.com",
                "Register a free account",
                "Navigate to https://dashboard.fullcontact.com",
                "Click on 'Get an API Key'",
                "Verify your account using your contact number",
                "The API Key will be listed under 'Your API Keys'"
            ],
            'favIcon': "https://1a3asl4eps7u26kl661u3bi9-wpengine.netdna-ssl.com/wp-content/uploads/2019/11/cropped-full-contact-isologo-32x32.png",
            'logo': "https://1a3asl4eps7u26kl661u3bi9-wpengine.netdna-ssl.com/wp-content/themes/fc-theme/assets/images/common/full-contact-logo.svg?1574450351",
            'description': "Connecting data. Consolidating identities. Applying insights. Amplifying media reach. "
                                "We provide person-centered identity resolution to improve your customer interactions with a simple, "
                                "real-time API integration.\n"
                                "FullContact is a privacy-safe Identity Resolution company building trust between people and brands. "
                                "We deliver the capabilities needed to create tailored customer experiences by unifying data and "
                                "applying insights in the moments that matter.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "max_age_days": "365"
    }

    # Option descriptions
    optdescs = {
        "api_key": "Fullcontact.com API key.",
        "max_age_days": "Maximum number of age in days for a record before it's considered invalid and not reported."
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
        return ["DOMAIN_NAME", "EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "RAW_RIR_DATA",
                "PHONE_NUMBER", "GEOINFO", "PHYSICAL_ADDRESS"]

    def query(self, url, data, failcount=0):
        header = "Bearer " + self.opts['api_key']
        ret = None

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot", postData=json.dumps(data),
                               headers={"Authorization": header})

        if res['code'] in ["401", "400"]:
            self.sf.error("API key rejected by fullcontact.com", False)
            self.errorState = True
            return None

        if res['code'] == "403":
            if failcount == 3:
                self.sf.error("Throttled or other blocking by fullcontact.com", False)
                return None
            time.sleep(2)
            failcount += 1
            return self.query(url, data, failcount)

        if not res['content']:
            self.sf.error("No content returned from fullcontact.com", False)
            return None

        try:
            ret = json.loads(res['content'])
            if "updated" in ret and int(self.opts['max_age_days']) > 0:
                last_dt = datetime.strptime(ret['updated'], '%Y-%m-%d')
                last_ts = int(time.mktime(last_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * int(self.opts['max_age_days']))
                if last_ts < age_limit_ts:
                    self.sf.debug("Fullcontact.co record found but too old.")
                    return None
        except Exception as e:
            self.sf.error(f"Error processing JSON response from fullcontact.com: {e}", False)
            return None

        return ret

    def queryCompany(self, domain):
        url = "https://api.fullcontact.com/v3/company.enrich"
        return self.query(url, {"domain": domain})

    def queryPerson(self, name=None, email=None):
        url = "https://api.fullcontact.com/v3/person.enrich"
        q = dict()
        if not name and not email:
            return None

        if name:
            q['fullName'] = name
        if email:
            q['email'] = email

        return self.query(url, q)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts["api_key"] == "":
            self.sf.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!",
                False,
            )
            self.errorState = True
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            data = self.queryPerson(email=eventData)

            if not data:
                return None

            full_name = data.get('fullName')

            if not full_name:
                return None

            e = SpiderFootEvent("RAW_RIR_DATA", f"Possible full name: {full_name}", self.__name__, event)
            self.notifyListeners(e)
            return None

        if eventName == "DOMAIN_NAME":
            data = self.queryCompany(eventData)
            if not data:
                return None
            if data.get("details"):
                data = data['details']
            if data.get("emails"):
                for r in data['emails']:
                    if r['value'].split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"

                    e = SpiderFootEvent(evttype, r['value'], self.__name__, event)
                    self.notifyListeners(e)

            if data.get("phones"):
                for r in data['phones']:
                    e = SpiderFootEvent("PHONE_NUMBER", r['value'], self.__name__, event)
                    self.notifyListeners(e)

            if data.get("locations"):
                for r in data['locations']:
                    if r.get("city") and r.get("country"):
                        e = SpiderFootEvent("GEOINFO", r['city'] + ", " + r['country'],
                                            self.__name__, event)
                        self.notifyListeners(e)
                    if r.get("formatted"):
                        # Seems to contain some junk sometimes
                        if len(r['formatted']) > 10:
                            e = SpiderFootEvent("PHYSICAL_ADDRESS", r['formatted'],
                                                self.__name__, event)
                            self.notifyListeners(e)

            if data.get("keyPeople"):
                for r in data['keyPeople']:
                    if r.get('fullName'):
                        e = SpiderFootEvent(
                            "RAW_RIR_DATA",
                            "Possible full name: {r['fullName']}",
                            self.__name__,
                            event
                        )
                        self.notifyListeners(e)

# End of sfp_fullcontact class
