# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_cymon
# Purpose:      Query cymon
#
# Author:      Koen Van Impe
#
# Created:     23/12/2015
# Copyright:   (c) Koen Van Impe
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

import urllib
import urllib2

from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_cymon(SpiderFootPlugin):
    """Cymon:Investigate,Passive:Search Engines:apikey:Obtain information from Cymon, a tracker of open-source security reports."""

    # Default options
    opts = {
        "apikey": "",
        "query_events": True,
        "pagination_limit": 1000,
        "pagination_offset": 0
    }

    # Option descriptions
    optdescs = {
        "apikey": "Your CYMON API Key.",
        "query_events": "Query the 'events' API, can cause doubles when used with other modules (VirusTotal, etc.)",
        "pagination_limit": "The limit indicates the maximum number of items to return.",
        "pagination_offset": "The offset indicates the starting position of the query in relation to the complete set of unpaginated items."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

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

    def query(self, qry, querytype="domains"):
        ret = None
        querytype = str(querytype)
        if querytype not in ["domains", "urls", "events"]:
            querytype = "domains"

        htoken = "Token " + self.opts['apikey']
        headers = {'Authorization': htoken,}
        pagination_limit = int(self.opts['pagination_limit'])
        pagination_offset = int(self.opts['pagination_offset'])
        url = "https://cymon.io/api/nexus/v1/ip/" + urllib.quote(qry) + "/" + str(querytype) + "/?limit=" + str(pagination_limit) + "&offset=" + str(pagination_offset)
        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot", headers=headers)

        if res['content'] is None:
            self.sf.info("No Cymon info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from Cymon.", False)
            return None

        return info

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['apikey'] == "":
            self.sf.error("You enabled sfp_cymon but did not set an API key!", False)
            return None

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
            rec_domains = self.query(addr, "domains")
            rec_urls = self.query(addr, "urls")
            if self.checkForStop():
                return None

            if self.opts['query_events']:
                rec_events = self.query(addr, "events")
                if rec_events is not None:
                    results = rec_events.get("results", None)
                    count = rec_events.get("count", 0)
                else:
                    results = None
                if results is not None:
                    self.sf.info("Found " + str(count) + " event results in Cymon")
                    for eventid in results:
                        title = eventid.get("title")
                        details_url = eventid.get("details_url")
                        description = eventid.get("description")
                        tags = eventid.get("tags")
                        if tags is not None:
                            t = " ["
                            for tag in tags:
                                t = t + " " + str(tag)
                            tags = t + " ]"
                        else:
                            tags = ""
                        if details_url is not None:
                            url = details_url
                        else:
                            url = "https://cymon.io/" + str(addr)

                        infourl = "<SFURL>" + url + "</SFURL>"
                        evt = "DESCRIPTION_ABSTRACT"
                        entry = title + tags + "\n" + infourl
                        e = SpiderFootEvent(evt, entry, self.__name__, event)
                        self.notifyListeners(e) 

            try:
                results = rec_domains.get("results", None)
                count = rec_domains.get("count",0)
            except:
                self.sf.error("Domain set empty for Cymon", False)
                return None

            if results is not None:
                self.sf.info("Found " + str(count) + " domain results in Cymon")

                for domains in results:
                    domain = domains.get("name")
                    if domain is not None:
                        evt = "DNS_PASSIVE"
                        e = SpiderFootEvent(evt, domain, self.__name__, event)
                        self.notifyListeners(e)  

            results = rec_urls.get("results")
            count = rec_urls.get("count",0)

            if results is not None:
                self.sf.info("Found " + str(count) + " URL results in Cymon")

                for urls in results:
                    url = urls["location"]
                    if url is not None:
                        evt = "URL_MALICIOUS"
                        e = SpiderFootEvent(evt, url, self.__name__, event)
                        self.notifyListeners(e)               
# End of sfp_cymon class
