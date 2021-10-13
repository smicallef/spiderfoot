# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_cleantalk
# Purpose:     Checks if a netblock or IP address is on CleanTalk.org's spam IP list.
#
# Author:      steve@binarypool.com
#
# Created:     05/08/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_cleantalk(SpiderFootPlugin):

    meta = {
        'name': "CleanTalk Spam List",
        'summary': "Check if a netblock or IP address is on CleanTalk.org's spam IP list.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cleantalk.org",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cleantalk.org/help",
                "https://cleantalk.org/help/introduction",
                "https://cleantalk.org/help/api-spam-check",
                "https://cleantalk.org/wordpress-security-malware-firewall",
                "https://cleantalk.org/price-anti-spam",
                "https://cleantalk.org/ssl-certificates/cheap-positivessl-certificate",
                "https://cleantalk.org/email-checker",
                "https://cleantalk.org/blacklists"
            ],
            'favIcon': "https://cleantalk.org/favicons/favicon-16x16.png",
            'logo': "https://cleantalk.org/favicons/favicon-16x16.png",
            'description': "CleanTalk is a Cloud-Based spam filtering service that allows you to protect your website from spam. "
            "CleanTalk provides spam protection that invisible to visitors "
            "without using captcha or other methods when visitors have to prove that they are real people.\n"
            "CleanTalk provides cloud anti-spam solutions for CMS and we developed plugins for the most of popular "
            "CMS: WordPress anti-spam plugin, Joomla anti-spam plugin, Drupal and etc. "
            "With our simple cloud spam checker, you can be sure your website is protected from spam bots, spam comments, and users.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliate IP addresses?",
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

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER'
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
        ]

    def query(self, qry, targetType):
        cid = "_cleantalk"
        url = "https://iplists.firehol.org/files/cleantalk_7d.ipset"

        data = dict()
        data["content"] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))

        if data["content"] is None:
            data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if data["code"] != "200":
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            if data["content"] is None:
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            self.sf.cachePut("sfmal_" + cid, data['content'])

        for line in data["content"].split('\n'):
            ip = line.strip().lower()

            if ip.startswith('#'):
                continue

            if targetType == "netblock":
                try:
                    if IPAddress(ip) in IPNetwork(qry):
                        self.debug(f"{ip} found within netblock/subnet {qry} in CleanTalk Spam List.")
                        return url
                except Exception as e:
                    self.debug(f"Error encountered parsing: {e}")
                    continue

            if targetType == "ip":
                if qry.lower() == ip:
                    self.debug(f"{qry} found in CleanTalk Spam List.")
                    return url

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} with CleanTalk Spam List")

        url = self.query(eventData, targetType)

        if not url:
            return

        self.debug(f"{eventData} found in Cleantalk Spam List")

        text = f"CleanTalk Spam List [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_cleantalk class
