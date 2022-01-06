# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_intelx
# Purpose:      Query IntelligenceX (intelx.io) for identified IP addresses,
#               domains, e-mail addresses and phone numbers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     28/04/2019
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_intelx(SpiderFootPlugin):

    meta = {
        'name': "IntelligenceX",
        'summary': "Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://intelx.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://ginseg.com/wp-content/uploads/sites/2/2019/07/Manual-Intelligence-X-API.pdf",
                "https://blog.intelx.io/2019/01/25/new-developer-tab/",
                "https://github.com/IntelligenceX/SDK"
            ],
            'apiKeyInstructions': [
                "Visit https://intelx.io/",
                "Register a free account",
                "Navigate to https://intelx.io/account?tab=developer",
                "The API key is listed under 'Your API details'"
            ],
            'favIcon': "https://intelx.io/favicon/favicon-32x32.png",
            'logo': "https://intelx.io/assets/img/IntelligenceX.svg",
            'description': "Intelligence X is an independent European technology company founded in 2018 by Peter Kleissner. "
            "Its mission is to develop and maintain the search engine and data archive.\n"
            "The search works with selectors, i.e. specific search terms such as "
            "email addresses, domains, URLs, IPs, CIDRs, Bitcoin addresses, IPFS hashes, etc.\n"
            "It searches in places such as the darknet, document sharing platforms, whois data, public data leaks and others.\n"
            "It keeps a historical data archive of results, "
            "similar to how the Wayback Machine from archive.org stores historical copies of websites.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "base_url": "2.intelx.io",
        "checkcohosts": False,
        "checkaffiliates": False,
        'netblocklookup': False,
        'maxnetblock': 24,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxage': 90
    }

    # Option descriptions
    optdescs = {
        "api_key": "IntelligenceX API key.",
        "base_url": "API URL, as provided in your IntelligenceX account settings.",
        "checkcohosts": "Check co-hosted sites?",
        "checkaffiliates": "Check affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxage': "Maximum age (in days) of results to be considered valid. 0 = unlimited."
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME", "EMAILADDR",
                "CO_HOSTED_SITE", "PHONE_NUMBER", "BITCOIN_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["LEAKSITE_URL", "DARKNET_MENTION_URL",
                "INTERNET_NAME", "DOMAIN_NAME",
                "EMAILADDR", "EMAILADDR_GENERIC"]

    def query(self, qry, qtype):
        retdata = list()

        headers = {
            "User-Agent": "SpiderFoot",
            "x-key": self.opts['api_key'],
        }

        payload = {
            "term": qry,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 100,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": []
        }

        url = 'https://' + self.opts['base_url'] + '/' + qtype + '/search'
        res = self.sf.fetchUrl(url, postData=json.dumps(payload),
                               headers=headers, timeout=self.opts['_fetchtimeout'])

        if res['content'] is None:
            self.info("No IntelligenceX info found for " + qry)
            return None

        if res['code'] == "402":
            self.info("IntelligenceX credits expired.")
            self.errorState = True
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from IntelligenceX: {e}")
            self.errorState = True
            return None

        if ret.get('status', -1) == 0:
            # Craft API URL with the id to return results
            resulturl = f"{url}/result?id={ret['id']}"
            limit = 30
            count = 0
            status = 3  # status 3 = No results yet, keep trying. 0 = Success with results
            while status in [3, 0] and count < limit:
                if self.checkForStop():
                    return None

                res = self.sf.fetchUrl(resulturl, headers=headers)
                if res['content'] is None:
                    self.info("No IntelligenceX info found for results from " + qry)
                    return None

                if res['code'] == "402":
                    self.info("IntelligenceX credits expired.")
                    self.errorState = True
                    return None

                try:
                    ret = json.loads(res['content'])
                except Exception as e:
                    self.error("Error processing JSON response from IntelligenceX: " + str(e))
                    return None

                status = ret['status']
                count += 1

                retdata.append(ret)
                # No more results left
                if status == 1:
                    # print data in json format to manipulate as desired
                    break

                time.sleep(1)

        return retdata

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "" or self.opts['base_url'] == "":
            self.error("You enabled sfp_intelx but did not set an API key and/or base URL!")
            self.errorState = True
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return

        data = self.query(eventData, "intelligent")
        if data is None:
            return

        self.info("Found IntelligenceX leak data for " + eventData)
        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])
        for info in data:
            for rec in info.get("records", dict()):
                try:
                    last_seen = int(datetime.datetime.strptime(rec['added'].split(".")[0], '%Y-%m-%dT%H:%M:%S').strftime('%s')) * 1000
                    if self.opts['maxage'] > 0 and last_seen < agelimit:
                        self.debug("Record found but too old, skipping.")
                        continue

                    val = None
                    evt = None
                    if "pastes" in rec['bucket']:
                        evt = "LEAKSITE_URL"
                        val = rec['keyvalues'][0]['value']
                    if rec['bucket'].startswith("darknet."):
                        evt = "DARKNET_MENTION_URL"
                        val = rec['name']

                    if not val or not evt:
                        # Try generically extracting it
                        if "systemid" not in rec:
                            continue
                        evt = "LEAKSITE_URL"
                        val = "https://intelx.io/?did=" + rec['systemid']
                except Exception as e:
                    self.error(f"Error processing content from IntelX: {e}")
                    continue

                # Notify other modules of what you've found
                e = SpiderFootEvent(evt, val, self.__name__, event)
                self.notifyListeners(e)

        if "public.intelx.io" in self.opts['base_url'] or eventName != "INTERNET_NAME":
            return

        data = self.query(eventData, "phonebook")
        if data is None:
            return

        self.info(f"Found IntelligenceX host and email data for {eventData}")
        for info in data:
            for rec in info.get("selectors", dict()):
                try:
                    val = rec['selectorvalueh']
                    evt = None
                    if rec['selectortype'] == 1:  # Email
                        evt = "EMAILADDR"
                        if val.split("@")[0] in self.opts['_genericusers'].split(","):
                            evt = "EMAILADDR_GENERIC"
                    if rec['selectortype'] == 2:  # Domain
                        evt = "INTERNET_NAME"
                        if val == eventData:
                            continue
                    if rec['selectortype'] == 3:  # URL
                        evt = "LINKED_URL_INTERNAL"

                    if not val or not evt:
                        self.debug("Unexpected record, skipping.")
                        continue
                except Exception as e:
                    self.error(f"Error processing content from IntelX: {e}")
                    continue

                # Notify other modules of what you've found
                e = SpiderFootEvent(evt, val, self.__name__, event)
                self.notifyListeners(e)

                if evt == "INTERNET_NAME" and self.sf.isDomain(val, self.opts['_internettlds']):
                    e = SpiderFootEvent("DOMAIN_NAME", val, self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_intelx class
