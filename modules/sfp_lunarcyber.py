# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_lunarcyber
# Purpose:      Query Lunar's Domain Exposure API for domain-level exposure data
#               related to infostealer logs and data breaches.
#
# Created:     2026-08-13
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_lunarcyber(SpiderFootPlugin):

    meta = {
        'name': "Lunar Cyber",
        'summary': "Query Lunar's Domain Exposure API for domain-level exposure data related to infostealer logs and data breaches.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://lunarcyber.com",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://lunarcyber.com/domain-exposure",
                "https://api.lunarcyber.com/domain-exposure?domain=stryker.com"
            ],
            'favIcon': "https://lunarcyber.com/favicon.ico",
            'logo': "https://lunarcyber.com/domain-exposure/assets/lunar-wordmark.svg",
            'description': "Lunar is a free, enterprise-grade, compromised-credentials monitoring "
                           "platform, available to every company, everywhere. It detects exposure "
                           "tied to your domain across infostealer logs, database breaches, combo "
                           "lists, and leaked cookies and sessions, unified into a single events feed.",
        }
    }

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_INTERNET_NAME", "RAW_RIR_DATA"]

    # Query the Lunar Domain Exposure API
    def query(self, qry):
        """Query the Lunar Domain Exposure API.

        Args:
            qry (str): domain name

        Returns:
            dict: API response
        """

        params = urllib.parse.urlencode({
            'domain': qry
        })

        res = self.sf.fetchUrl(
            f"https://api.lunarcyber.com/domain-exposure?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        return res

    def parseApiResponse(self, res):
        """Parse the API response.

        Args:
            res (dict): response from self.sf.fetchUrl()

        Returns:
            dict: parsed JSON response
        """

        if not res:
            self.debug("No response from Lunar Cyber API.")
            return None

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Lunar Cyber API.")
            return None

        if res['content'] is None:
            self.debug("Received no content from Lunar Cyber API.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from Lunar Cyber API: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        res = self.query(eventData)

        if not res:
            self.info(f"No response from Lunar Cyber API for {eventData}.")
            return

        data = self.parseApiResponse(res)

        if not data:
            self.debug(f"No data returned from Lunar Cyber API for {eventData}.")
            return

        if data.get('status') != 'REPORT_READY':
            self.info(f"No exposure report available from Lunar Cyber for {eventData} (status: {data.get('status')}).")
            return

        report = data.get('report')

        if not report:
            self.debug(f"Lunar Cyber API response for {eventData} contains no report data.")
            return

        summary = report.get('summary', {})

        if not summary.get('total_events'):
            self.info(f"No exposure events found for {eventData} from Lunar Cyber.")
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", str(report), self.__name__, event)
        self.notifyListeners(evt)

        description = self._describeExposure(eventData, summary, report)

        evt = SpiderFootEvent("MALICIOUS_INTERNET_NAME", description, self.__name__, event)
        self.notifyListeners(evt)

    def _describeExposure(self, eventData, summary, report):
        """Build a human-readable exposure description.

        Args:
            eventData (str): the queried domain
            summary (dict): report summary
            report (dict): full report

        Returns:
            str: description
        """

        total = summary.get('total_events', 0)
        infostealer = summary.get('infostealer_events', 0)
        breach = summary.get('data_breach_events', 0)

        parts = [f"Lunar Cyber: {total} exposure(s) found for {eventData}"]

        if infostealer:
            parts.append(f"{infostealer} infostealer")

        if breach:
            parts.append(f"{breach} data breach")

        families = []
        for entry in report.get('malware_family_breakdown', []):
            if isinstance(entry, dict) and entry.get('family'):
                families.append(str(entry.get('family')))

        if families:
            parts.append(f"malware: {', '.join(families[:10])}")

        return ", ".join(parts)

# End of sfp_lunarcyber class
