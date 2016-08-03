# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_virustotal
# Purpose:      Query VirusTotal for identified IP addresses.
#
# Author:      Steve Micallef <steve@binarypool.com> ; Koen Van Impe
#
# Created:     21/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import datetime
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_virustotal(SpiderFootPlugin):
    """VirusTotal:Investigate,Passive:Blacklists:apikey:Obtain information from VirusTotal about identified IP addresses."""

    # Default options
    opts = {
        "apikey": "",
        "publicapi": True,
        "checkcohosts": True,
        "checkaffiliates": True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
        'insert_urls': True,
        'insert_resolve': True,
        'insert_date': True,
        'insert_detected_downloaded_samples': True,
        'insert_undetected_downloaded_samples': True
    }

    # Option descriptions
    optdescs = {
        "apikey": "Your VirusTotal API Key.",
        "publicapi": "Are you using a public key? If so SpiderFoot will pause for 15 seconds after each query to avoid VirusTotal dropping requests.",
        "checkcohosts": "Check co-hosted sites?",
        "checkaffiliates": "Check affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "insert_urls": "Add found URLs to database",
        "insert_resolve": "Add found DNS resolves to database",
        'insert_undetected_downloaded_samples': "Add undetected samples (SHA1 hash) to the database",
        'insert_detected_downloaded_samples': "Add undetected samples (SHA1 hash) to the database",
        "insert_date": "Use the date of detection (true) or date of SF scan (false) for malicious url and passive DNS"        
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

    def query(self, qry):
        ret = None

        if self.sf.validIP(qry):
            url = "https://www.virustotal.com/vtapi/v2/ip-address/report?ip=" + qry 
        else:
            url = "https://www.virustotal.com/vtapi/v2/domain/report?domain=" + qry

        res = self.sf.fetchUrl(url + "&apikey=" + self.opts['apikey'],
                               timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot")

        # Public API is limited to 4 queries per minute
        if self.opts['publicapi']:
            time.sleep(15)

        if res['content'] is None:
            self.sf.info("No VirusTotal info found for " + qry)
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from VirusTotal.", False)
            return None

        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['apikey'] == "":
            self.sf.error("You enabled sfp_virustotal but did not set an API key!", False)
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return None

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return None

        if eventName == 'NETBLOCK_OWNER' and self.opts['netblocklookup']:
            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.sf.debug("Network size bigger than permitted: " +
                              str(IPNetwork(eventData).prefixlen) + " > " +
                              str(self.opts['maxnetblock']))
                return None

        if eventName == 'NETBLOCK_MEMBER' and self.opts['subnetlookup']:
            if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                self.sf.debug("Network size bigger than permitted: " +
                              str(IPNetwork(eventData).prefixlen) + " > " +
                              str(self.opts['maxsubnet']))
                return None

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

            # Treat siblings as affiliates if they are of the original target, otherwise
            # they are additional hosts within the target.
            if 'domain_siblings' in info:
                if eventName in [ "IP_ADDRESS", "INTERNET_NAME"]:
                    for s in info['domain_siblings']:
                        if self.getTarget().matches(s):
                            if s not in self.results:
                                e = SpiderFootEvent("INTERNET_NAME", s, self.__name__, event)
                                self.notifyListeners(e)
                        else:
                            if s not in self.results:
                                e = SpiderFootEvent("AFFILIATE_INTERNET_NAME", s, self.__name__, event)
                                self.notifyListeners(e)
                    
            if 'subdomains' in info and eventName == "INTERNET_NAME":
                for n in info['subdomains']:
                    if n not in self.results:
                        e = SpiderFootEvent("INTERNET_NAME", n, self.__name__, event)
                        self.notifyListeners(e)
                                        
            if 'detected_urls' in info:
                self.sf.info("Found VirusTotal URL data (detected_urls) for " + addr)
                if eventName in ["IP_ADDRESS"] or eventName.startswith("NETBLOCK_"):
                    evt = "MALICIOUS_IPADDR"
                    infotype = "ip-address"

                if eventName == "AFFILIATE_IPADDR":
                    evt = "MALICIOUS_AFFILIATE_IPADDR"
                    infotype = "ip-address"

                if eventName == "INTERNET_NAME":
                    evt = "MALICIOUS_INTERNET_NAME"
                    infotype = "domain"

                if eventName == "AFFILIATE_INTERNET_NAME":
                    evt = "MALICIOUS_AFFILIATE_INTERNET_NAME"
                    infotype = "domain"

                if eventName == "CO_HOSTED_SITE":
                    evt = "MALICIOUS_COHOST"
                    infotype = "domain"

                infourl = "<SFURL>https://www.virustotal.com/en/" + infotype + "/" + \
                          addr + "/information/</SFURL>"

                # Notify other modules of what you've found
                e = SpiderFootEvent(evt, "VirusTotal [" + addr + "]\n" +
                                    infourl, self.__name__, event)
                self.notifyListeners(e)

                if self.opts['insert_urls']:
                    detected_urls = info["detected_urls"]
                    if detected_urls is not None:
                        evt = "URL_MALICIOUS"
                        infotype = "domain"                        
                        for detected_url in detected_urls:    
                            url = detected_url["url"]
                            e = SpiderFootEvent(evt, url, self.__name__, event)
                            if self.opts['insert_date']:
                                detectdate = detected_url["scan_date"]
                                detectdate = time.mktime(datetime.datetime.strptime(detectdate, "%Y-%m-%d %H:%M:%S").timetuple())
                                e.updateGenerated(detectdate)

                            self.notifyListeners(e)

            if self.opts['insert_resolve']:
                if 'resolutions' in info:
                    self.sf.info("Found VirusTotal URL data (resolutions) for " + addr)
                    evt = "DNS_PASSIVE"
                    resolutions = info["resolutions"]
                    if resolutions is not None:
                        for resolve in resolutions:
                            try:
                                domain = resolve["hostname"]
                                e = SpiderFootEvent(evt, domain, self.__name__, event)
                                if self.opts['insert_date']:
                                    detectdate = resolve["last_resolved"]
                                    detectdate = time.mktime(datetime.datetime.strptime(detectdate, "%Y-%m-%d %H:%M:%S").timetuple())
                                    e.updateGenerated(detectdate)
                                self.notifyListeners(e)
                            except:
                                continue
                                
            if self.opts['insert_undetected_downloaded_samples']:
                if 'undetected_downloaded_samples' in info:
                    self.sf.info("Found VirusTotal URL data (undetected_downloaded_samples) for " + addr)
                    evt = "FILE_DETECTED"
                    undetected_downloaded_samples = info["undetected_downloaded_samples"]
                    if undetected_downloaded_samples is not None:
                        for sample in undetected_downloaded_samples:
                            sha256hash = sample["sha256"]
                            e = SpiderFootEvent(evt, sha256hash, self.__name__, event)
                            self.notifyListeners(e)     
            if self.opts['insert_detected_downloaded_samples']:
                if 'detected_downloaded_samples' in info:
                    self.sf.info("Found VirusTotal URL data (detected_downloaded_samples) for " + addr)
                    evt = "FILE_UNDETECTED"
                    detected_downloaded_samples = info["detected_downloaded_samples"]
                    if detected_downloaded_samples is not None:
                        for sample in detected_downloaded_samples:
                            sha256hash = sample["sha256"]
                            e = SpiderFootEvent(evt, sha256hash, self.__name__, event)
                            self.notifyListeners(e)     
# End of sfp_virustotal class
