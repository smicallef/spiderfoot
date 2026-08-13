# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_lunarcyber
# Purpose:      Query Lunar's Domain Exposure API for domain-level exposure
#               data related to infostealer logs and data breaches.
#
# Author:       <your-github-username>
#
# Created:     11/08/2026
# Copyright:   (c) TrueFurina 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_lunarcyber(SpiderFootPlugin):

    meta = {
        'name': "Lunar Cyber",
        'summary': "Query Lunar's Domain Exposure API for domain-level exposure data related to infostealer logs and data breaches.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://lunarcyber.com",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://api.lunarcyber.com/domain-exposure"
            ],
            'favIcon': "",
            'logo': "",
            'description': "Lunar provides domain-level exposure data related to infostealer logs and data breaches, "
            "including exposure counts, recent activity, malware families, affected services, and infected device metadata.",
        }
    }

    opts = {
        'exposure_limit_days': 365,
        'verify': True
    }

    optdescs = {
        'exposure_limit_days': "Maximum age (in days) of exposure events to consider relevant.",
        'verify': "Verify host resolves."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Lunar Cyber"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["INTERNET_NAME", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["MALICIOUS_INTERNET_NAME"]

    def handleEvent(self, event):
        eventData = event.data
        eventType = event.eventType

        if eventData in self.results:
            return
        self.results[eventData] = True

        if not self.sf.validHost(eventData, self.opts['_internettlds']):
            self.debug(f"Skipping {eventData} as it is not a valid host.")
            return

        url = f"https://api.lunarcyber.com/domain-exposure?domain={eventData}"
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['code'] != '200':
            self.error(f"Lunar Cyber API returned an unexpected response code: {res['code']}")
            return

        if not res.get('content'):
            self.debug("No content returned from Lunar Cyber API")
            return

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from Lunar Cyber API: {e}")
            return

        exposures = self._extractExposures(data)
        if not exposures:
            self.info(f"No domain exposure data found for {eventData}")
            return

        for exposure in exposures:
            evt = SpiderFootEvent("MALICIOUS_INTERNET_NAME", exposure, self.__name__, event)
            self.notifyListeners(evt)

    def _extractExposures(self, data):
        """Defensively extract exposure descriptions from the API response.

        The Lunar Domain Exposure API returns domain-level exposure data for
        infostealer logs and data breaches. Accept a dict (single domain) or a
        list of records; each record may carry exposure counts, malware
        families and affected services.
        """
        records = []
        if isinstance(data, dict):
            if isinstance(data.get('results'), list):
                records = data['results']
            elif data.get('domain') or data.get('domain_exposure'):
                records = [data]
            else:
                return []
        elif isinstance(data, list):
            records = data
        else:
            return []

        out = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            count = rec.get('exposure_count') or rec.get('total_exposures') or rec.get('count') or 0
            if not count:
                continue
            families = rec.get('malware_families') or []
            if isinstance(families, list):
                families = ", ".join(str(f) for f in families[:10])
            else:
                families = str(families)
            msg = f"Lunar Cyber: {count} exposure(s) found for this domain"
            if families:
                msg += f" ({families})"
            out.append(msg)
        return out

# End of sfp_lunarcyber class
