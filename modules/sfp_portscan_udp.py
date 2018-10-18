# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_portscan_udp
# Purpose:      SpiderFoot plug-in for performing a basic UDP port scan for
#               commonly open UDP ports using HackerTarget.com UDP port scan.
#
# Author:      Brendan Coles <bcoles@gmail.com>
#
# Created:     2018-10-19
# Copyright:   (c) Brendan Coles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_portscan_udp(SpiderFootPlugin):
    """Port Scanner - UDP:Footprint,Investigate:Crawling and Scanning:invasive:Scans for commonly open UDP ports on Internet-facing systems using HackerTarget.com UDP port scan."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "HackerTarget"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    def producedEvents(self):
        return ['UDP_PORT_OPEN']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        res = self.sf.fetchUrl("https://hackertarget.com/udp-port-scan/", timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'],
                               postData="theinput=" + eventData + "&thetest=udpscan&name_of_nonce_field=&_wp_http_referer=%2Fudp-port-scan%2F")

        if res['content'] is None:
            return None

        html_data = re.findall(r'<pre id="formResponse">(.*?)</pre>', res['content'], re.MULTILINE | re.DOTALL)

        if html_data is None:
            self.sf.debug("Found no open UDP ports on " + eventData)
            return None

        open_ports = re.findall(r'(\d+)/udp\s+open\s+', html_data[0])

        if open_ports is None:
            self.sf.debug("Found no open UDP ports on " + eventData)
            return None

        self.sf.debug("Found " + str(len(open_ports)) + " open UDP ports on " + eventData)

        for port in open_ports:
            e = SpiderFootEvent("UDP_PORT_OPEN", port, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_portscan_udp class
