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
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_securitytrails(SpiderFootPlugin):
    """SecurityTrails:Investigate,Passive:Search Engines:apikey:Obtain Passive DNS and other information from SecurityTrails"""

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

    results = dict()
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME", 
                "EMAILADDR", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["CO_HOSTED_SITE", "AFFILIATE_DOMAIN", "INTERNET_NAME",
                "PROVIDER_HOSTING"]

    # Verify a host resolves to an IP
    def validateIP(self, host, ip):
        try:
            addrs = socket.gethostbyname_ex(host)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

        for addr in addrs:
            if type(addr) == list:
                for a in addr:
                    if str(a) == ip:
                        return True
            else:
                if str(addr) == ip:
                    return True
        return False

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

        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot", headers=headers,
                               postData=request)

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("SecurityTrails API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No SecurityTrails info found for " + qry)
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
                    return self.query(qry, querytype, page+1, accum)
                else:
                    # We are at the last page
                    accum.extend(info.get('records', []))
                    return accum
            else:
                return info.get('records', [])
        except Exception as e:
            self.sf.error("Error processing JSON response from SecurityTrails: " + str(e), False)
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_securitytrails but did not set an API uid/secret!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName in [ "IP_ADDRESS", "IPV6_ADDRESS", "NETLBLOCK_OWNER"]:
            ip = eventData
            rec = self.query(ip, "ipv4")
            myres = list()
            hosters = list()
            if rec is not None:
                for r in rec:
                    if "host_provider" in r:
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
                        if not self.opts['cohostsamedomain']:
                            if self.getTarget().matches(h, includeParents=True):
                                self.sf.debug("Skipping " + h + " because it is on the same domain.")
                                continue

                        if h not in myres and h != ip:
                            if self.opts['verify'] and not self.validateIP(h, ip):
                                self.sf.debug("Host " + h + " no longer resolves to our IP.")
                                continue
                        myres.append(h.lower())
                        e = SpiderFootEvent("CO_HOSTED_SITE", h, self.__name__, event)
                        self.notifyListeners(e)
                        self.cohostcount += 1

        if eventName in [ "EMAILADDR"]:
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
                        e = SpiderFootEvent("AFFILIATE_DOMAIN", h, self.__name__, event)
                        self.notifyListeners(e)

        if eventName in [ "DOMAIN_NAME"]:
            domain = eventData
            rec = self.query(domain, "domain")
            myres = list()
            if rec is not None:
                for h in rec:
                    if h.lower() not in myres:
                        myres.append(h.lower())
                    else:
                        continue
                    e = SpiderFootEvent("INTERNET_NAME", h + "." + domain, 
                                        self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_securitytrails class
