# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_abuseipdb
# Purpose:     Check if an IP address is malicious according to AbuseIPDB.com.
#
# Author:      steve@binarypool.com
#
# Created:     06/09/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_abuseipdb(SpiderFootPlugin):

    meta = {
        'name': "AbuseIPDB",
        'summary': "Check if an IP address is malicious according to AbuseIPDB.com blacklist.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.abuseipdb.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.abuseipdb.com/#introduction",
                "https://www.abuseipdb.com/fail2ban.html",
                "https://www.abuseipdb.com/csf",
                "https://www.abuseipdb.com/suricata",
                "https://www.abuseipdb.com/splunk",
                "https://www.abuseipdb.com/categories"
            ],
            'apiKeyInstructions': [
                "Visit https://www.abuseipdb.com/pricing",
                "Select the plan required",
                "Register a new account with an email",
                "Navigate to https://www.abuseipdb.com/account/api",
                "The API Key is listed under 'Keys'"
            ],
            'favIcon': "https://www.abuseipdb.com/favicon.ico",
            'logo': "https://www.abuseipdb.com/img/abuseipdb.png.pagespeed.ce.CI8T6WsXU7.png",
            'description': "AbuseIPDB is a project dedicated to helping combat the spread of hackers,"
            "spammers, and abusive activity on the internet.\n"
            "Our mission is to help make Web safer by providing a central blacklist for"
            "webmasters, system administrators, and other interested parties to"
            "report and find IP addresses that have been associated with malicious activity online."
        }
    }

    opts = {
        'api_key': '',
        'confidenceminimum': 90,
        'checkaffiliates': True,
        'limit': 10000
    }

    optdescs = {
        'api_key': "AbuseIPDB.com API key.",
        'confidenceminimum': "The minimium AbuseIPDB confidence level to require.",
        'checkaffiliates': "Apply checks to affiliates?",
        'limit': 'Maximum number of results to retrieve.',
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

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

    def queryBlacklist(self):
        blacklist = self.sf.cacheGet('abuseipdb', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        headers = {
            'Key': self.opts['api_key'],
            'Accept': "text/plain"
        }

        params = urllib.parse.urlencode({
            'confidenceMinimum': self.opts['confidenceminimum'],
            'limit': self.opts['limit'],
            'plaintext': '1'
        })

        res = self.sf.fetchUrl(
            f"https://api.abuseipdb.com/api/v2/blacklist?{params}",
            timeout=60,  # retrieving 10,000 results (default) or more can sometimes take a while
            useragent=self.opts['_useragent'],
            headers=headers
        )

        time.sleep(1)

        if res['code'] == '429':
            self.error("You are being rate-limited by AbuseIPDB")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error(f"Error retrieving search results, code {res['code']}")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error("Error retrieving search results from AbuseIPDB")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from AbuseIPDB")
            self.errorState = True
            return None

        self.sf.cachePut("abuseipdb", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from AbuseIPDB

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for ip in blacklist.split('\n'):
            ip = ip.strip()
            if ip.startswith('#'):
                continue
            if not self.sf.validIP(ip) and not self.sf.validIP6(ip):
                continue
            ips.append(ip)

        return ips

    def queryIpAddress(self, ip):
        """Query API for an IPv4 or IPv6 address.

        Note: Currently unused.

        Args:
            ip (str): IP address

        Returns:
            str: API response as JSON
        """

        headers = {
            'Key': self.opts['api_key'],
            'Accept': 'application/json',
        }

        params = urllib.parse.urlencode({
            'ipAddress': ip,
            'maxAgeInDays': 30,
        })

        res = self.sf.fetchUrl(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            headers=headers
        )

        time.sleep(1)

        if res['code'] == '429':
            self.error("You are being rate-limited by AbuseIPDB")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error("Error retrieving search results from AbuseIPDB")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from AbuseIPDB")
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        return None

    def queryNetblock(self, ip):
        """Query API for a netblock.

        Note: Currently unused.

        Args:
            ip (str): CIDR range

        Returns:
            str: API response as JSON
        """

        headers = {
            'Key': self.opts['api_key'],
            'Accept': 'application/json',
        }

        params = urllib.parse.urlencode({
            'ipAddress': ip,
            'maxAgeInDays': 30,
        })

        res = self.sf.fetchUrl(
            f"https://api.abuseipdb.com/api/v2/check-block?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            headers=headers
        )

        time.sleep(1)

        if res['code'] == '429':
            self.error("You are being rate-limited by AbuseIPDB")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error("Error retrieving search results from AbuseIPDB")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from AbuseIPDB")
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

        self.debug(f"Checking maliciousness of IP address {eventData} with AbuseIPDB")

        blacklist = self.queryBlacklist()

        if not blacklist:
            return

        if eventData not in blacklist:
            return

        self.info(f"Malicious IP address {eventData} found in AbuseIPDB blacklist")

        url = f"https://www.abuseipdb.com/check/{eventData}"

        evt = SpiderFootEvent(
            malicious_type,
            f"AbuseIPDB [{eventData}]\n<SFURL>{url}</SFURL>",
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        evt = SpiderFootEvent(
            blacklist_type,
            f"AbuseIPDB [{eventData}]\n<SFURL>{url}</SFURL>",
            self.__name__,
            event
        )
        self.notifyListeners(evt)

# End of sfp_abuseipdb class
