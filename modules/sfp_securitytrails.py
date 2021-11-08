# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_securitytrails
# Purpose:      Query securitytrails using their API
#
# Author:      Steve Micallef
#
# Created:     01/02/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_securitytrails(SpiderFootPlugin):

    meta = {
        'name': "SecurityTrails",
        'summary': "Obtain Passive DNS and other information from SecurityTrails",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://securitytrails.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.securitytrails.com/docs",
                "https://docs.securitytrails.com/reference#general"
            ],
            'apiKeyInstructions': [
                "Visit https://securitytrails.com",
                "Register a free account",
                "Navigate to https://securitytrails.com/app/account/credentials",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://securitytrails.com/user/themes/lego/favicon/apple-touch-icon.png",
            'logo': "https://securitytrails.com/user/themes/lego/favicon/apple-touch-icon.png",
            'description': "Data for Security companies, researchers and teams. Fast, always up API that "
            "allows you to access current and historical data. "
            "The API is paid via a simple pricing structure that allows you to embed our data into your applications.\n"
            "Search nearly 3 billion historical and current WHOIS data and WHOIS changes.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "verify": True,
        "cohostsamedomain": False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        "api_key": "SecurityTrails API key.",
        "verify": "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME",
                "EMAILADDR", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["CO_HOSTED_SITE",
                "DOMAIN_NAME", "AFFILIATE_DOMAIN_NAME",
                "INTERNET_NAME", "AFFILIATE_INTERNET_NAME",
                "PROVIDER_HOSTING"]

    # Search SecurityTrails
    def query(self, qry, querytype, page=1, accum=None):
        info = None

        headers = {
            'APIKEY': self.opts['api_key']
        }

        if querytype == "domain":
            url = "https://api.securitytrails.com/v1/domain/" + qry + "/subdomains"
            request = None
        else:
            url = "https://api.securitytrails.com/v1/search/list/?page=" + str(page)
            request = '{"filter": { "' + querytype + '": "' + qry + '" } }'
            headers['Content-Type'] = 'application/json'

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot", headers=headers,
                               postData=request)

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("SecurityTrails API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info("No SecurityTrails info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
            if querytype == "domain":
                return info.get('subdomains', None)
            if info.get("record_count", 0) > 100:
                if len(info.get('records', [])) >= 100:
                    # Avoid throttling
                    time.sleep(1)
                    if accum:
                        accum.extend(info.get('records'))
                    else:
                        accum = info.get('records')
                    return self.query(qry, querytype, page + 1, accum)
                else:
                    # We are at the last page
                    accum.extend(info.get('records', []))
                    return accum
            else:
                return info.get('records', [])
        except Exception as e:
            self.error("Error processing JSON response from SecurityTrails: " + str(e))
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_securitytrails but did not set an API uid/secret!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS", "NETLBLOCK_OWNER"]:
            ip = eventData
            rec = self.query(ip, "ipv4")
            myres = list()
            hosters = list()
            if rec is not None:
                for r in rec:
                    if "host_provider" in r:
                        if not r['host_provider']:
                            continue
                        for dat in r['host_provider']:
                            if dat in hosters:
                                continue
                            e = SpiderFootEvent("PROVIDER_HOSTING", dat,
                                                self.__name__, event)
                            self.notifyListeners(e)
                            hosters.append(dat)
                    if "hostname" in r:
                        if self.cohostcount > self.opts['maxcohost']:
                            continue

                        h = r['hostname']
                        if not h:
                            continue
                        if not self.opts['cohostsamedomain']:
                            if self.getTarget().matches(h, includeParents=True):
                                self.debug("Skipping " + h + " because it is on the same domain.")
                                continue

                        if h not in myres and h != ip:
                            if self.opts['verify'] and not self.sf.validateIP(h, ip):
                                self.debug("Host " + h + " no longer resolves to our IP.")
                                continue
                        myres.append(h.lower())
                        e = SpiderFootEvent("CO_HOSTED_SITE", h, self.__name__, event)
                        self.notifyListeners(e)
                        self.cohostcount += 1

        if eventName in ["EMAILADDR"]:
            email = eventData
            rec = self.query(email, "whois_email")
            myres = list()
            if rec is not None:
                for r in rec:
                    if "hostname" in r:
                        if not r['hostname']:
                            continue
                        h = r['hostname']
                        if h.lower() not in myres:
                            myres.append(h.lower())
                        else:
                            continue
                        e = SpiderFootEvent("AFFILIATE_INTERNET_NAME", h, self.__name__, event)
                        self.notifyListeners(e)

                        if self.sf.isDomain(h, self.opts['_internettlds']):
                            evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", h, self.__name__, event)
                            self.notifyListeners(evt)

        if eventName in ["DOMAIN_NAME"]:
            domain = eventData
            rec = self.query(domain, "domain")
            myres = list()
            if rec is not None:
                for h in rec:
                    if h == "":
                        continue
                    if h.lower() not in myres:
                        myres.append(h.lower())
                    else:
                        continue
                    e = SpiderFootEvent("INTERNET_NAME", h + "." + domain,
                                        self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_securitytrails class
