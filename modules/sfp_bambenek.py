# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bambenek
# Purpose:      Checks if an IP, hostname or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     07/09/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

malchecks = {
    'Bambenek C&C IP List': {
        'id': 'bambip',
        'checks': ['ip', 'netblock'],
        'url': 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt',
        'regex': '^{0},.*'
    },
    'Bambenek C&C Domain List': {
        'id': 'bambdom',
        'checks': ['domain'],
        'url': 'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt',
        'regex': '^{0},.*'
    }
}


class sfp_bambenek(SpiderFootPlugin):

    meta = {
        'name': "Bambenek C&C List",
        'summary': "Check if a host/domain or IP appears on Bambenek Consulting's C&C tracker lists.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.bambenekconsulting.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.bambenekconsulting.com/free-osint-tools/",
                "https://osint.bambenekconsulting.com/feeds/",
                "https://osint.bambenekconsulting.com/feeds/license.txt"
            ],
            'favIcon': "http://www.bambenekconsulting.com/wp-content/uploads/2013/04/mini-logo1.ico",
            'logo': "http://www.bambenekconsulting.com/wp-content/uploads/2013/04/logo_transparent21-300x84.png",
            'description': "Bambenek Consulting is an cybersecurity investigations and intelligence consulting firm "
            "focusing on tackling major criminal threats. "
            "Every day, there is another story about another company having their banking accounts drained, "
            "someone having their identity stolen, or critical infrastructure being taken offline by hostile entities. "
            "Led by IT security expert, John Bambenek, we have the resources to bring to your business so "
            "you can be sure your organization and your customers’ data is safe.",
        }
    }

    # Default options
    opts = {
        'bambip': True,
        'bambdom': True,
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'bambip': "Enable Bambenek IP check?",
        'bambdom': "Enable Bambenek Domains check?",
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS",
                "NETBLOCK_MEMBER", "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
                "CO_HOSTED_SITE", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_SUBNET", "MALICIOUS_COHOST", "MALICIOUS_NETBLOCK"]

    # Look up 'list' type resources
    def resourceList(self, replaceme_id, target, targetType):
        targetDom = ''
        # Get the base domain if we're supplied a domain
        if targetType == "domain":
            targetDom = self.sf.hostDomain(target, self.opts['_internettlds'])
            if not targetDom:
                return None

        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if replaceme_id == cid:
                data = dict()
                url = malchecks[check]['url']
                data['content'] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))
                if data['content'] is None:
                    data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
                    if data['content'] is None:
                        self.sf.error("Unable to fetch " + url)
                        return None
                    else:
                        self.sf.cachePut("sfmal_" + cid, data['content'])

                # If we're looking at netblocks
                if targetType == "netblock":
                    iplist = list()
                    # Get the regex, replace {0} with an IP address matcher to
                    # build a list of IP.
                    # Cycle through each IP and check if it's in the netblock.
                    if 'regex' in malchecks[check]:
                        rx = malchecks[check]['regex'].replace("{0}", r"(\d+\.\d+\.\d+\.\d+)")
                        pat = re.compile(rx, re.IGNORECASE)
                        self.sf.debug("New regex for " + check + ": " + rx)
                        for line in data['content'].split('\n'):
                            grp = re.findall(pat, line)
                            if len(grp) > 0:
                                # self.sf.debug("Adding " + grp[0] + " to list.")
                                iplist.append(grp[0])
                    else:
                        iplist = data['content'].split('\n')

                    for ip in iplist:
                        if len(ip) < 8 or ip.startswith("#"):
                            continue
                        ip = ip.strip()

                        try:
                            if IPAddress(ip) in IPNetwork(target):
                                self.sf.debug(f"{ip} found within netblock/subnet {target} in {check}")
                                return url
                        except Exception as e:
                            self.sf.debug(f"Error encountered parsing: {e}")
                            continue

                    return None

                # If we're looking at hostnames/domains/IPs
                if 'regex' not in malchecks[check]:
                    for line in data['content'].split('\n'):
                        if line == target or (targetType == "domain" and line == targetDom):
                            self.sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                            return url
                else:
                    try:
                        # Check for the domain and the hostname
                        rxDom = str(malchecks[check]['regex']).format(targetDom)
                        rxTgt = str(malchecks[check]['regex']).format(target)
                        for line in data['content'].split('\n'):
                            if (targetType == "domain" and re.match(rxDom, line, re.IGNORECASE)) or \
                                    re.match(rxTgt, line, re.IGNORECASE):
                                self.sf.debug(target + "/" + targetDom + " found in " + check + " list.")
                                return url
                    except Exception as e:
                        self.sf.debug("Error encountered parsing 2: " + str(e))
                        continue

        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.sf.debug("Checking maliciousness of " + target + " (" + itemType + ") with: " + cid)
                return self.resourceList(cid, target, itemType)

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts.get('checkcohosts', False):
            return
        if eventName == 'AFFILIATE_IPADDR' \
                and not self.opts.get('checkaffiliates', False):
            return
        if eventName == 'NETBLOCK_OWNER' and not self.opts.get('checknetblocks', False):
            return
        if eventName == 'NETBLOCK_MEMBER' and not self.opts.get('checksubnets', False):
            return

        for check in list(malchecks.keys()):
            cid = malchecks[check]['id']

            if eventName in ['IP_ADDRESS', 'AFFILIATE_IPADDR']:
                typeId = 'ip'
                if eventName == 'IP_ADDRESS':
                    evtType = 'MALICIOUS_IPADDR'
                else:
                    evtType = 'MALICIOUS_AFFILIATE_IPADDR'

            if eventName in ['INTERNET_NAME', 'CO_HOSTED_SITE',
                             'AFFILIATE_INTERNET_NAME']:
                typeId = 'domain'
                if eventName == "INTERNET_NAME":
                    evtType = "MALICIOUS_INTERNET_NAME"
                if eventName == 'AFFILIATE_INTERNET_NAME':
                    evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
                if eventName == 'CO_HOSTED_SITE':
                    evtType = 'MALICIOUS_COHOST'

            if eventName == 'NETBLOCK_OWNER':
                typeId = 'netblock'
                evtType = 'MALICIOUS_NETBLOCK'
            if eventName == 'NETBLOCK_MEMBER':
                typeId = 'netblock'
                evtType = 'MALICIOUS_SUBNET'

            url = self.lookupItem(cid, typeId, eventData)

            if self.checkForStop():
                return

            # Notify other modules of what you've found
            if url is not None:
                text = f"{check} [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_bambenek class
