# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_censys
# Purpose:     Query Censys.io API
#
# Author:      Steve Micallef
#
# Created:     01/02/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import time
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_censys(SpiderFootPlugin):

    meta = {
        'name': "Censys",
        'summary': "Obtain information from Censys.io",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://censys.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://censys.io/api",
                "https://censys.io/product",
                "https://censys.io/ipv4"
            ],
            'apiKeyInstructions': [
                "Visit https://censys.io/",
                "Register a free account",
                "Navigate to https://censys.io/account",
                "Click on 'API'",
                "The API key combination is listed under 'API ID' and 'Secret'"
            ],
            'favIcon': "https://censys.io/assets/favicon.png",
            'logo': "https://censys.io/assets/logo.png",
            'description': "Discover exposures and other common entry points for attackers.\n"
            "Censys scans the entire internet constantly, including obscure ports. "
            "We use a combination of banner grabs and deep protocol handshakes "
            "to provide industry-leading visibility and an accurate depiction of what is live on the internet.",
        }
    }

    opts = {
        "censys_api_key_uid": "",
        "censys_api_key_secret": "",
        'delay': 3,
        "age_limit_days": 90
    }

    optdescs = {
        "censys_api_key_uid": "Censys.io API UID.",
        "censys_api_key_secret": "Censys.io API Secret.",
        'delay': 'Delay between requests, in seconds.',
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "BGP_AS_MEMBER",
            "TCP_PORT_OPEN",
            "OPERATING_SYSTEM",
            "WEBSERVER_HTTPHEADERS",
            "NETBLOCK_MEMBER",
            "GEOINFO",
            "RAW_RIR_DATA"
        ]

    def queryIp(self, qry):
        secret = self.opts['censys_api_key_uid'] + ':' + self.opts['censys_api_key_secret']
        auth = base64.b64encode(secret.encode('utf-8')).decode('utf-8')

        headers = {
            'Authorization': f"Basic {auth}"
        }

        res = self.sf.fetchUrl(
            f"https://search.censys.io/api/v2/hosts/{qry}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        # API rate limit: 0.4 actions/second (120.0 per 5 minute interval)
        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    def parseApiResponse(self, res):
        if not res:
            return None

        if res['code'] == "400":
            self.sf.error("Invalid request.")
            return None

        if res['code'] == "404":
            self.sf.info('Censys.io returned no resuls')
            return None

        if res['code'] == "403":
            self.sf.error("Invalid API key.")
            self.errorState = True
            return None

        if res['code'] == "429":
            self.sf.error("Request rate limit exceeded.")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from Censys API")
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info('Censys.io returned no resuls')
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from Censys.io: {e}")

        error_type = data.get('error_type')
        if error_type:
            self.sf.error(f"Censys returned an unexpected error: {error_type}")
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['censys_api_key_uid'] == "" or self.opts['censys_api_key_secret'] == "":
            self.sf.error("You enabled sfp_censys but did not set an API uid/secret!")
            self.errorState = True
            return

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

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
                return

            if eventName in ["IP_ADDRESS", "NETBLOCK_OWNER"]:
                rec = self.queryIp(addr)

            rec = rec.get("result")

            if rec is None:
                continue

            self.sf.debug("Found results in Censys.io")

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName.startswith('NETBLOCK_'):
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(rec), self.__name__, pevent)
            self.notifyListeners(e)

            try:
                # Date format: 2021-09-22T16:46:47.623Z
                created_dt = datetime.strptime(rec.get('last_updated_at', "1970-01-01T00:00:00.000Z"), '%Y-%m-%dT%H:%M:%S.%fZ')
                created_ts = int(time.mktime(created_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])

                if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                    self.sf.debug("Record found but too old, skipping.")
                    continue

                if 'location' in rec:
                    location = ', '.join([_f for _f in [rec['location'].get('city'), rec['location'].get('province'), rec['location'].get('postal_code'), rec['location'].get('country')] if _f])
                    if location:
                        e = SpiderFootEvent("GEOINFO", location, self.__name__, pevent)
                        self.notifyListeners(e)

                for service in rec['services']:
                    try:
                        headers = service['http']['response']['headers']
                    except Exception:
                        headers = None

                    if headers:
                        dat = json.dumps(headers, ensure_ascii=False)
                        e = SpiderFootEvent("WEBSERVER_HTTPHEADERS", dat, self.__name__, pevent)
                        e.actualSource = addr
                        self.notifyListeners(e)

                    try:
                        transportFingerprint = service["transport_fingerprint"]
                    except Exception:
                        transportFingerprint = None

                    if transportFingerprint:
                        if 'os' in transportFingerprint:
                            e = SpiderFootEvent("OPERATING_SYSTEM", transportFingerprint["os"], self.__name__, pevent)
                            self.notifyListeners(e)

                if 'autonomous_system' in rec:
                    dat = str(rec['autonomous_system']['asn'])
                    e = SpiderFootEvent("BGP_AS_MEMBER", dat, self.__name__, pevent)
                    self.notifyListeners(e)

                    dat = rec['autonomous_system']['bgp_prefix']
                    e = SpiderFootEvent("NETBLOCK_MEMBER", dat, self.__name__, pevent)
                    self.notifyListeners(e)

                if 'protocols' in rec:
                    for p in rec['protocols']:
                        if 'ip' not in rec:
                            continue
                        dat = rec['ip'] + ":" + p.split("/")[0]
                        e = SpiderFootEvent("TCP_PORT_OPEN", dat, self.__name__, pevent)
                        self.notifyListeners(e)

            except Exception as e:
                self.sf.error(f"Error encountered processing record for {eventData} ({e})")

# End of sfp_censys class
