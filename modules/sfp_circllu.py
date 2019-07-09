# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_circllu
# Purpose:      Query circl.lu using their API
#
# Author:      Steve Micallef
#
# Created:     16/02/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import base64
from datetime import datetime
import re
import time
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_circllu(SpiderFootPlugin):
    """CIRCL.LU:Investigate,Passive:Reputation Systems:apikey:Obtain information from CIRCL.LU's Passive DNS and Passive SSL databases."""

    # Default options
    opts = {
        "api_key_login": "",
        "api_key_password": "",
        "age_limit_days": 0,
        "verify": True,
        "cohostsamedomain": False,
        "maxcohost": 100
    }

    # Option descriptions
    optdescs = {
        "api_key_login": "CIRCL.LU login.",
        "api_key_password": "CIRCL.LU password.",
        "age_limit_days": "Ignore any Passive DNS records older than this many days. 0 = unlimited.",
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

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

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

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "NETBLOCK_OWNER", "IP_ADDRESS", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "SSL_CERTIFICATE_ISSUED", 
                "CO_HOSTED_SITE"]

    def query(self, qry, qtype):
        ret = None

        if self.errorState:
            return None

        if qtype == "PDNS":
            url = "https://www.circl.lu/pdns/query/" + qry
        else:
            url = "https://www.circl.lu/v2pssl/query/" + qry

        cred = base64.b64encode(self.opts['api_key_login'] + ":" + self.opts['api_key_password'])
        headers = {
            'Authorization': "Basic " + cred
        }

        # Be more forgiving with the timeout as some queries for subnets can be slow
        res = self.sf.fetchUrl(url , timeout=30, 
                               useragent="SpiderFoot", headers=headers)

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("CIRCL.LU access seems to have been rejected or you have exceeded usage limits.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No CIRCL.LU info found for " + qry)
            return None

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        ret = None

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Ignore messages from myself
        if srcModuleName == "sfp_circllu":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return None

        if self.opts['api_key_login'] == "" or self.opts['api_key_password'] == "":
            self.sf.error("You enabled sfp_circllu but did not set an credentials!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName in [ 'IP_ADDRESS', 'NETBLOCK_OWNER' ]:
            # CIRCL.LU limit the maximum subnet size to 23
            # http://circl.lu/services/passive-ssl/
            if "/" in eventData:
                addr, mask = eventData.split("/")
                if int(mask) < 23:
                    self.sf.debug("Network size bigger than permitted by CIRCL.LU.")
                else:
                    ret = self.query(eventData, "PSSL")
                    if not ret:
                        self.sf.info("No CIRCL.LU passive SSL data found for " + eventData)
            else:
                ret = self.query(eventData, "PSSL")
                if not ret:
                    self.sf.info("No CIRCL.LU passive SSL data found for " + eventData)

            if ret:
                try:
                    # Generate an event for the IP first, and then link the cert
                    # to that event.
                    j = json.loads(ret)
                    for ip in j:
                        ipe = event
                        if ip != eventData:
                            ipe = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                            self.notifyListeners(ipe)
                        for crt in j[ip]['subjects']:
                            r = re.findall(".*[\"\'](.+CN=([a-zA-Z0-9\-\*\.])+)[\"\'].*", 
                                           str(j[ip]['subjects'][crt]), re.IGNORECASE)
                            if r:
                                e = SpiderFootEvent("SSL_CERTIFICATE_ISSUED", r[0][0], self.__name__, ipe)
                                self.notifyListeners(e)
                except BaseException as e:
                    self.sf.error("Invalid response returned from CIRCL.LU: " + str(e), False)

        if eventName in [ 'IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME' ]:
            ret = self.query(eventData, "PDNS")
            if not ret:
                self.sf.info("No CIRCL.LU passive DNS data found for " + eventData)
                return None

            # CIRCL.LU doesn't return valid JSON - it's one JSON record per line
            for line in ret.split("\n"):
                if len(line) < 2:
                    continue
                try:
                    rec = json.loads(line)
                except BaseException as e:
                    self.sf.error("Invalid response returned from CIRCL.LU: " + str(e), False)
                    continue

                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                if self.opts['age_limit_days'] > 0 and rec['time_last'] < age_limit_ts:
                    self.sf.debug("Record found but too old, skipping.")
                    continue

                cohosts = list()
                if eventName == "IP_ADDRESS":
                    # Record could be pointing to our IP, or from our IP
                    if rec['rrtype'] == "A" and rec['rdata'] == eventData:
                        if not self.getTarget().matches(rec['rrname']):
                            # We found a co-host
                            cohosts.append(rec['rrname'])

                if eventName in [ "INTERNET_NAME", "DOMAIN_NAME" ]:
                    # Record could be an A/CNAME of this entity, or something pointing to it
                    if rec['rdata'] == eventData:
                        if not self.getTarget().matches(rec['rrname']):
                            # We found a co-host
                            cohosts.append(rec['rrname'])

                for co in cohosts:
                    if eventName == "IP_ADDRESS" and (self.opts['verify'] and not self.validateIP(co, eventData)):
                        self.sf.debug("Host no longer resolves to our IP.")
                        continue

                    if not self.opts['cohostsamedomain']:
                        if self.getTarget().matches(co, includeParents=True):
                            self.sf.debug("Skipping " + co + " because it is on the same domain.")
                            continue

                    if self.cohostcount < self.opts['maxcohost']:
                        e = SpiderFootEvent("CO_HOSTED_SITE", co, self.__name__, event)
                        self.notifyListeners(e)
                        self.cohostcount += 1

# End of sfp_circllu class
