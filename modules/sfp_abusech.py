# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_abusech
# Purpose:     Check if a host/domain, IP address or netblock is malicious according
#              to Abuse.ch.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_abusech(SpiderFootPlugin):

    meta = {
        'name': "abuse.ch",
        'summary': "Check if a host/domain, IP address or netblock is malicious according to Abuse.ch.",
        'flags': [],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.abuse.ch",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://feodotracker.abuse.ch/",
                "https://sslbl.abuse.ch/",
                "https://urlhaus.abuse.ch/",
            ],
            'apiKeyInstructions': [
                "Visit https://bazaar.abuse.ch/api#api_key",
                "Login using a Twitter Account",
                "Navigate to 'Account Settings'",
                "The API key is listed under 'Your API Key'",
                "Visit https://urlhaus.abuse.ch/api/",
                "Login using a Twitter Account at https://urlhaus.abuse.ch/login/",
                "Navigate to https://urlhaus.abuse.ch/api/#account",
                "The API Key is listed under 'API-Key'"
            ],
            'favIcon': "https://abuse.ch/favicon.ico",
            'logo': "https://abuse.ch/images/abusech.svg",
            'description': "abuse.ch is operated by a random swiss guy fighting malware for non-profit, "
            "running a couple of projects helping internet service providers and "
            "network operators protecting their infrastructure from malware.\n"
            "IT-Security researchers, vendors and law enforcement agencies rely on data from abuse.ch,"
            "trying to make the internet a safer place.",
        }
    }

    # Default options
    opts = {
        'abusefeodoip': True,
        'abusesslblip': True,
        'abuseurlhaus': True,
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'abusefeodoip': "Enable abuse.ch Feodo IP check?",
        'abusesslblip': "Enable abuse.ch SSL Backlist IP check?",
        'abuseurlhaus': "Enable abuse.ch URLhaus check?",
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "IP_ADDRESS",
            "NETBLOCK_MEMBER",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE",
            "NETBLOCK_OWNER"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_SUBNET",
            "MALICIOUS_COHOST",
            "MALICIOUS_NETBLOCK"
        ]

    def queryFeodoTrackerBlacklist(self, target, targetType):
        blacklist = self.retrieveFeodoTrackerBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Abuse.ch Feodo Tracker.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Abuse.ch Feodo Tracker.")
                    return True

        return False

    def retrieveFeodoTrackerBlacklist(self):
        blacklist = self.sf.cacheGet('abusech_feodo', 24)

        if blacklist is not None:
            return self.parseFeodoTrackerBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Abuse.ch Abuse.ch Feodo Tracker.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Abuse.ch Feodo Tracker")
            self.errorState = True
            return None

        self.sf.cachePut("abusech_feodo", res['content'])

        return self.parseFeodoTrackerBlacklist(res['content'])

    def parseFeodoTrackerBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from Abuse.ch Feodo Tracker

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for ip in blacklist.split('\n'):
            ip = ip.strip()
            if not ip:
                continue
            if ip.startswith('#'):
                continue
            if not self.sf.validIP(ip):
                continue
            ips.append(ip)

        return ips

    def querySslBlacklist(self, target, targetType):
        blacklist = self.retrieveSslBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Abuse.ch SSL Blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Abuse.ch SSL Blacklist.")
                    return True

        return False

    def retrieveSslBlacklist(self):
        blacklist = self.sf.cacheGet('abusech_ssl', 24)

        if blacklist is not None:
            return self.parseSslBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Abuse.ch Abuse.ch Feodo Tracker.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Abuse.ch Feodo Tracker")
            self.errorState = True
            return None

        self.sf.cachePut("abusech_ssl", res['content'])

        return self.parseSslBlacklist(res['content'])

    def parseSslBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): CSV blacklist from Abuse.ch SSL Blacklist

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for line in blacklist.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            csv = line.split(',')
            if len(csv) < 2:
                continue
            ip = csv[1]
            if not self.sf.validIP(ip):
                continue
            ips.append(ip)

        return ips

    def queryUrlHausBlacklist(self, target, targetType):
        blacklist = self.retrieveUrlHausBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Abuse.ch URL Haus Blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Abuse.ch URL Haus Blacklist.")
                    return True
        elif targetType == "domain":
            if target.lower() in blacklist:
                self.debug(f"Host name {target} found in Abuse.ch URL Haus Blacklist.")
                return True

        return False

    def retrieveUrlHausBlacklist(self):
        blacklist = self.sf.cacheGet('abusech_urlhaus', 24)

        if blacklist is not None:
            return self.parseUrlHausBlacklist(blacklist)

        res = self.sf.fetchUrl(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Abuse.ch URL Haus.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Abuse.ch URL Haus")
            self.errorState = True
            return None

        self.sf.cachePut("abusech_urlhaus", res['content'])

        return self.parseUrlHausBlacklist(res['content'])

    def parseUrlHausBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from Abuse.ch URL Haus

        Returns:
            list: list of blacklisted hosts
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue

            # Note: URL parsing and validation with sf.validHost() is too slow to use here
            url = line.strip().lower()
            if len(url.split("/")) < 3:
                continue
            host = url.split("/")[2].split(':')[0]
            if not host:
                continue
            if "." not in host:
                continue
            hosts.append(host)

        return hosts

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            evtType = 'MALICIOUS_IPADDR'
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_NETBLOCK'
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_SUBNET'
        elif eventName == "INTERNET_NAME":
            targetType = 'domain'
            evtType = "MALICIOUS_INTERNET_NAME"
        elif eventName == 'AFFILIATE_INTERNET_NAME':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'domain'
            evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
        elif eventName == 'CO_HOSTED_SITE':
            if not self.opts.get('checkcohosts', False):
                return
            targetType = 'domain'
            evtType = 'MALICIOUS_COHOST'
        else:
            return

        if targetType in ['ip', 'netblock']:
            self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Abuse.ch Feodo Tracker")
            if self.queryFeodoTrackerBlacklist(eventData, targetType):
                url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
                text = f"Abuse.ch Feodo Tracker [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

            self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Abuse.ch SSL Blacklist")
            if self.querySslBlacklist(eventData, targetType):
                url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
                text = f"Abuse.ch SSL Blacklist [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

        if targetType in ['ip', 'domain']:
            self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Abuse.ch URL Haus")
            if self.queryUrlHausBlacklist(eventData, targetType):
                url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
                text = f"Abuse.ch URL Haus Blacklist [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_abusech class
