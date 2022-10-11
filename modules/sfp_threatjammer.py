# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_threatjammer
# Purpose:     Check if an IP or netblock is malicious according to ThreatJammer.com.
#
# Author:      diego.parrilla.santamaria@gmail.com
#
# Created:     2022-05-03
# Copyright:   (c) Diego Parrilla 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_threatjammer(SpiderFootPlugin):

    meta = {
        'name': "Threat Jammer",
        'summary': "Check if an IP address is malicious according to ThreatJammer.com",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://threatjammer.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://threatjammer.com/docs/what-is-threat-jammer",
                "https://threatjammer.com/docs/how-threat-jammer-works",
                "https://threatjammer.com/docs/introduction-threat-jammer-user-api",
                "https://threatjammer.com/docs/introduction-threat-jammer-report-api",
                "https://threatjammer.com/tutorials/how-to-configure-fail2ban-in-ubuntu",
                "https://threatjammer.com/tutorials/how-to-configure-cowrie-honeypot"
            ],
            'apiKeyInstructions': [
                "https://threatjammer.com/docs/threat-jammer-api-keys",
                "Register a new account with an email",
                "Navigate to https://threatjammer.com/keys",
                "The API Keys are listed under 'API Key' column"
            ],
            'favIcon': "https://threatjammer.com/favicon.ico",
            'logo': "https://threatjammer.com/threatjammer-risk-score.png",
            'description': "Threat Jammer is a service to access high-quality threat intelligence"
            " data from a variety of sources, and integrate it into their applications with the"
            " sole purpose of detecting and blocking malicious activity."
        }
    }

    opts = {
        'api_key': "",
        'api_hostname': "dublin.api.threatjammer.com",
        'risk_score_min': 35,
        'checkaffiliates': True,
    }

    optdescs = {
        'api_key': "Threat Jammer API key.",
        'api_hostname': "User API hostname",
        'risk_score_min': "Minimum Threat Jammer risk score",
        'checkaffiliates': "Apply checks to affiliates?",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
        ]

    def queryIp(self, ip):
        """Query API for an IPv4 or IPv6 address.

        Args:
            ip (str): IP address

        Returns:
            str: API response as JSON
        """

        headers = {
            'Authorization': f"Bearer {self.opts['api_key']}",
            'Accept': 'application/json',
        }

        res = self.sf.fetchUrl(
            f"https://{self.opts['api_hostname']}/v1/assess/ip/{ip}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            headers=headers
        )

        time.sleep(1)

        if res['code'] == '400':
            self.error("ThreatJammer.com rejected the IP address. Use only public IP addresses.")
            return None

        if res['code'] == '422':
            self.error("ThreatJammer.com could not process the IP address. Check the format.")
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by ThreatJammer.com")
            self.errorState = True
            return None

        if res['code'] == '401':
            self.error("You are not authorized by ThreatJammer.com. Check your API key.")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error("ThreatJammer.com could not process the IP address. Unknown error.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from ThreatJammer.com")
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if self.opts["api_hostname"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API hostname!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            blacklist_type = "BLACKLISTED_IPADDR"
            malicious_type = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
            malicious_type = 'MALICIOUS_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of IP address {eventData} with ThreatJammer.com")

        ip_info = self.queryIp(eventData)

        if ip_info is None:
            self.sf.error(f"Error processing JSON response for {eventData} from ThreatJammer.com")
            return

        score = ip_info.get('score')
        if not score:
            self.sf.error(f"No risk score found for {eventData} from ThreatJammer.com. Skipping.")
            return
        risk_score = int(score)

        risk = ip_info.get("risk")
        if not risk:
            self.sf.error(f"No risk type found for {eventData} from ThreatJammer.com. Skipping.")
            return

        if risk_score < self.opts["risk_score_min"]:
            self.debug(f"Skipping {eventData} for ThreatJammer.com, risk score below minimum threshold.")
            return

        url = "https://threatjammer.com/info/"
        detail = f"Risk score: {risk_score} ({risk})\n<SFURL>{url}{eventData}</SFURL>"

        self.info(f"Malicious IP address {eventData} found in any Threat Jammer lists")

        evt = SpiderFootEvent(
            malicious_type,
            f"Threat Jammer - {detail}",
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        evt = SpiderFootEvent(
            blacklist_type,
            f"Threat Jammer  - {detail}",
            self.__name__,
            event
        )
        self.notifyListeners(evt)

# End of sfp_threatjammer class
