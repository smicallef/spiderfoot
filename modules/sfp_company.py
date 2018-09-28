# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_company
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying company names.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     09/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

try:
    import re2 as re
except ImportError:
    import re

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_company(SpiderFootPlugin):
    """Company Names:Footprint,Investigate,Passive:Content Analysis::Identify company names in any obtained data."""


    # Default options
    opts = {
        # options specific to this module
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "SSL_CERTIFICATE_ISSUED", 
                "DOMAIN_WHOIS", "NETBLOCK_WHOIS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["COMPANY_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Various ways to identify companies in text
        # Support up to three word company names with each starting with
        # a capital letter, allowing for hyphens brackets and numbers within.
        pattern_prefix = "(?=[,;:\'\">\(= ]|^)\s?([A-Z0-9\(\)][A-Za-z0-9\-&,][^ \"\';:><]*)?\s?([A-Z0-9\(\)][A-Za-z0-9\-&,]?[^ \"\';:><]*|[Aa]nd)?\s?([A-Z0-9\(\)][A-Za-z0-9\-&,]?[^ \"\';:><]*)?\s+"
        pattern_match_re = [
            'LLC', 'L\.L\.C\.?', 'AG', 'A\.G\.?', 'GmbH', 'Pty\.?\s+Ltd\.?', 
            'Ltd\.?', 'Pte\.?', 'Inc\.?', 'INC\.?', 'Incorporated', 'Foundation',
            'Corp\.?', 'Corporation', 'SA', 'S\.A\.?', 'SIA', 'BV', 'B\.V\.?',
            'NV', 'N\.V\.?' 'PLC', 'Limited', 'Pvt\.?\s+Ltd\.?', 'SARL' ]
        pattern_match = [
            'LLC', 'L.L.C', 'AG', 'A.G', 'GmbH', 'Pty',
            'Ltd', 'Pte', 'Inc', 'INC', 'Foundation',
            'Corp', 'SA', 'S.A', 'SIA', 'BV', 'B.V',
            'NV', 'N.V' 'PLC', 'Limited', 'Pvt.', 'SARL' ]

        pattern_suffix = "(?=[ \.,:<\)\'\"]|$)"

        # Filter out anything from the company name which matches the below
        filterpatterns = [
            "Copyright",
            "\d{4}" # To catch years
        ]

        # Don't re-parse company names
        if eventName == "COMPANY_NAME":
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName + ": " + str(len(eventData)) + " bytes.")

        if type(eventData) not in [str, unicode]:
            try:
                if type(eventData) in [ list, dict ]:
                    eventData = str(eventData)
                else:
                    self.sf.debug("Unhandled type to find company names: " + \
                                  str(type(eventData)))
                    return None
            except BaseException as e:
                self.sf.debug("Unable to convert list/dict to string: " + str(e))
                return None

        # Strip out everything before the O=
        try:
            if eventName == "SSL_CERTIFICATE_ISSUED":
                eventData = eventData.split("O=")[1]
        except BaseException as e:
                self.sf.debug("Couldn't strip out O=, proceeding anyway...")

        # Find chunks of text containing what might be a company name first.
        # This is to avoid running very expensive regexps on large chunks of
        # data.
        chunks = list()
        for pat in pattern_match:
            start = 0
            m = eventData.find(pat, start)
            while m > 0:
                start = m - 100
                if start < 0:
                    start = 0
                end = m + 100
                if end >= len(eventData):
                    end = len(eventData)-1
                chunks.append(eventData[start:end])
                offset = m + len(pat)
                m = eventData.find(pat, offset)

        myres = list()
        for chunk in chunks:
            for pat in pattern_match_re:
                matches = re.findall(pattern_prefix + "(" + pat + ")" + pattern_suffix, chunk, re.MULTILINE)
                for match in matches:
                    matched = 0
                    for m in match:
                        if len(m) > 0:
                            matched += 1
                    if matched <= 1:
                        continue

                    fullcompany = ""
                    for m in match:
                        flt = False
                        for f in filterpatterns:
                            if re.match(f, m):
                               flt = True 
                        if not flt:
                            fullcompany += m + " "

                    fullcompany = re.sub("\s+", " ", fullcompany.strip())
                    
                    self.sf.info("Found company name: " + fullcompany)
                    if fullcompany in myres:
                        self.sf.debug("Already found from this source.")
                        continue
                    else:
                        myres.append(fullcompany)

                    evt = SpiderFootEvent("COMPANY_NAME", fullcompany, self.__name__, event)
                    if event.moduleDataSource:
                        evt.moduleDataSource = event.moduleDataSource
                    else:
                        evt.moduleDataSource = "Unknown"
                    self.notifyListeners(evt)

# End of sfp_company class
