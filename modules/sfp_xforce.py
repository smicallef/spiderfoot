# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_xforce
# Purpose:      Query XForce Exchange
#
# Author:      Koen Van Impe
#
# Created:     23/12/2015
# Copyright:   (c) Koen Van Impe
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import glob,os
import sys

import urllib
import urllib2

from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_xforce(SpiderFootPlugin):
    """XForce Exchange:Investigate,Intelligence:Obtain information from XForce Exchange"""

    # Default options
    opts = {
        "xforcetoken": "XFORCEtoken",
        "xforce_pdns": True,
        "xforce_history": False,
        "xforce_malware": True,
        "xforce_ipr": True,
        "infield_sep": "; "
    }

    # Option descriptions
    optdescs = {
        "xforcetoken": "The token file for interacting with XForce",
        "xforce_pdns": "Include passive DNS from XForce",
        "xforce_history": "Include the history record from XForce (can cause lots of doubles)",
        "xforce_malware": "Include malware found via XForce",
        "xforce_ipr": "Include the IP geo info via XForce",
        "infield_sep": "Separate fields in data found"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def xforce_gettoken(self, xforce_url):
        HOME = os.path.dirname(os.path.realpath(__file__))
        TOKEN = self.opts['xforcetoken']

        if os.path.isfile("./" + TOKEN):
            tokenf = open(HOME + "/" + TOKEN ,"r")
            token = tokenf.readline()
        else:
            data = urllib2.urlopen( xforce_url + "/auth/anonymousToken" )
            t = json.load(data)
            token = str(t['token'])
            tokenf = open(HOME + "/token","w")
            tokenf.write(token)
        return token

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME",
                "AFFILIATE_DOMAIN", "CO_HOSTED_SITE", "NETBLOCK_OWNER",
                "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_COHOST", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                "MALICIOUS_SUBNET",
                "FILE_UNDETECTED", "FILE_DETECTED", "DNS_PASSIVE", "URL_MALICIOUS"]

    def query(self, qry, querytype="ipr"):
        ret = None

        querytype = str(querytype)
        if querytype not in ["ipr", "ipr/history", "ipr/malware", "resolve"]:
            querytype = "ipr"

        xforce_url = "https://xforce-api.mybluemix.net:443"
        token = self.xforce_gettoken(xforce_url)
        htoken = "Bearer "+ token
        headers = {'Authorization': htoken,}
        url = xforce_url + "/" + querytype + "/" + qry
        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot", headers=headers)

        if res['content'] is None:
            self.sf.info("No XForce info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from XForce.", False)
            return None

        return info


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        infield_sep = self.opts['infield_sep']

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:

            if self.checkForStop():
                return None
                
            if self.opts['xforce_ipr']:
                rec = self.query(addr, "ipr")
                if rec is not None:
                    rec_geo = rec.get("geo", None)
                    if rec_geo is not None:
                        self.sf.info("Found IPR results in XForce")
                        evt = "GEOINFO"

                        country = rec_geo.get("country", "")
                        e = SpiderFootEvent(evt, country, self.__name__, event)
                        self.notifyListeners(e)

                        countrycode = rec_geo.get("countrycode", "")
                        e = SpiderFootEvent(evt, countrycode, self.__name__, event)
                        self.notifyListeners(e)

            if self.opts['xforce_history']:
                rec = self.query(addr, "ipr/history")
                if rec is not None:
                    rec_history = rec.get("history", None)
                    if rec_history is not None:
                        self.sf.info("Found history results in XForce")
                        for result in rec_history:
                            reasonDescription = result.get("reasonDescription", "")
                            created = result.get("created", "")
                            reason = result.get("reason", "")
                            score = result.get("score", 0)
                            cats = result.get("cats", None)
                            cats_description = ""
                            if cats is not None:
                                for cat in cats:
                                    cats_description = cats_description + cat + " "
                            evt = "DESCRIPTION_ABSTRACT"
                            entry = reason + infield_sep + \
                                        str(score) + infield_sep + \
                                        created  + infield_sep + \
                                        cats_description
                            e = SpiderFootEvent(evt, entry, self.__name__, event)
                            self.notifyListeners(e)

            if self.opts['xforce_malware']:
                rec = self.query(addr, "ipr/malware")
                if rec is not None:
                    rec_malware = rec.get("malware", None)
                    if rec_malware is not None:
                        self.sf.info("Found malware results in XForce")
                        for result in rec_malware:
                            count = result.get("count", "")
                            origin = result.get("origin", "")
                            domain = result.get("domain", "")
                            uri = result.get("uri", "")
                            md5 = result.get("md5", "")
                            lastseen = result.get("last", "")
                            firstseen = result.get("first", "")
                            family = result.get("family", None)
                            family_description = ""
                            if family is not None:
                                for f in family:
                                    family_description = family_description + f + " "
                            evt = "MALICIOUS_IPADDR"
                            entry = origin + infield_sep + \
                                        family_description + infield_sep + \
                                        md5 + infield_sep + \
                                        domain + infield_sep + \
                                        uri + infield_sep + \
                                        firstseen + infield_sep + \
                                        lastseen
                            e = SpiderFootEvent(evt, entry, self.__name__, event)
                            self.notifyListeners(e)

            if self.opts['xforce_pdns']:
                rec = self.query(addr, "resolve")
                if rec is not None:
                    rec_passive = rec.get("Passive", None)
                    if rec_passive is not None:
                        rec_precords = rec_passive.get("records", None)
                        if rec_precords is not None:
                            self.sf.info("Found PDNS results in XForce")
                            for result in rec_precords:
                                value = result.get("value", "")
                                rtype = result.get("recordType", "")
                                lastseen = result.get("last", "")
                                firstseen = result.get("first", "")
                                evt = "DNS_PASSIVE"
                                entry = value + infield_sep + \
                                            firstseen + infield_sep + \
                                            lastseen + infield_sep + \
                                            rtype
                                e = SpiderFootEvent(evt, entry, self.__name__, event)
                                self.notifyListeners(e)

# End of sfp_xforce class
