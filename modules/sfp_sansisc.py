# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sans_isc
# Purpose:      Query ISC SANS for identified IP addresses. Note, IP malware checks on ISC are also in sfp_malcheck
#
# Author:      Koen Van Impe
#
# Created:     22/12/2015
# Copyright:   (c) Koen Van Impe
# Licence:     GPL
# -------------------------------------------------------------------------------


from xml.etree import cElementTree as ET
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_sansisc(SpiderFootPlugin):
    """SANS_ISC:Investigate,Passive:Blacklists::Obtain information from SANS ISC about identified IP addresses."""

    # Default options
    opts = {
        "include_geoinfo": True    
    }

    # Option descriptions
    optdescs = {
        "include_geoinfo": "Include GEOINFO from results (ASN, Country, etc.). False limits to network block."
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["GEOINFO","MALICIOUS_IPADDR",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                "MALICIOUS_SUBNET"]

    def query(self, qry):
        ret = None

        if self.sf.validIP(qry):
            url = "https://isc.sans.edu/api/ip/" + qry 

        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot")

        if res['content'] is None:
            self.sf.info("No SANS ISC info found for " + qry)
            return None

        try:
            root = ET.fromstring(res['content'])

            # Check if we can get any data from the XML tree
            ipnumber = root.findall("number")[0].text

        except Exception as e:
            self.sf.error("Error processing response from SANS ISC.", False)
            return None

        return root

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

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

            info = self.query(addr)

            if info is None:
                continue

            network = info.findall("network")[0].text
            if network is not None:
                evt = "MALICIOUS_SUBNET"
                e = SpiderFootEvent(evt, network, self.__name__, event)
                self.notifyListeners(e)     

            if self.opts['include_geoinfo']:
                asabusecontact = info.findall("asabusecontact")[0].text
                asn = info.findall("as")[0].text
                asname = info.findall("asname")[0].text
                ascountry = info.findall("ascountry")[0].text

                '''
                attacks = info.findall("attacks")[0].text
                count = info.findall("count")[0].text
                maxdate = info.findall("maxdate")[0].text
                mindate = info.findall("mindate")[0].text
                updated = info.findall("updated")[0].text
                comment = info.findall("comment")[0].text
                if count is None:
                    count = 0
                if attacks is None:
                    attacks = 0
                '''

                if asabusecontact is not None:
                    evt = "GEOINFO"
                    e = SpiderFootEvent(evt, asabusecontact, self.__name__, event)
                    self.notifyListeners(e)

                if asn is not None:
                    evt = "GEOINFO"
                    e = SpiderFootEvent(evt, asn, self.__name__, event)
                    self.notifyListeners(e)

                if asname is not None:
                    evt = "GEOINFO"
                    e = SpiderFootEvent(evt, asname, self.__name__, event)
                    self.notifyListeners(e)

                if ascountry is not None:
                    evt = "GEOINFO"
                    e = SpiderFootEvent(evt, ascountry, self.__name__, event)
                self.notifyListeners(e)
             
# End of sfp_sansisc class
