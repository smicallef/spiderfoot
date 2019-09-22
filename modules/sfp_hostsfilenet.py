# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_hostsfilenet
# Purpose:      Checks if an ASN, IP or domain is malicious.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

malchecks = {
    'hosts-file.net Malicious Hosts': {
        'id': '_hphosts',
        'type': 'list',
        'checks': ['domain'],
        'url': 'http://hosts-file.net/download/hosts.txt'
    }
}


class sfp_hostsfilenet(SpiderFootPlugin):
    """hosts-file.net Malicious Hosts:Investigate,Passive:Reputation Systems::Check if a host/domain is malicious according to hosts-file.net Malicious Hosts."""


    # Default options
    opts = {
        '_hphosts': True,
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'cacheperiod': "Hours to cache list data before re-fetching."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME", "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_INTERNET_NAME", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_COHOST"]

    # Look up 'list' type resources
    def resourceList(self, id, target, targetType):
        targetDom = ''
        # Get the base domain if we're supplied a domain
        if targetType == "domain":
            targetDom = self.sf.hostDomain(target, self.opts['_internettlds'])

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if id == cid and malchecks[check]['type'] == "list":
                data = dict()
                url = malchecks[check]['url']
                data['content'] = self.sf.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))
                if data['content'] is None:
                    data = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
                    if data['content'] is None:
                        self.sf.error("Unable to fetch " + url, False)
                        return None
                    else:
                        self.sf.cachePut("sfmal_" + cid, data['content'])

                # Check for the domain and the hostname
                if targetType == "domain" and "127.0.0.1\t" + targetDom + "\n" in data['content']:
                    self.sf.debug(targetDom + " found in " + check + " list.")
                    return url
                if "127.0.0.1\t" + target + "\n" in data['content']:
                    self.sf.debug(target + " found in " + check + " list.")
                    return url
        return None

    def lookupItem(self, resourceId, itemType, target):
        for check in malchecks.keys():
            cid = malchecks[check]['id']
            if cid == resourceId and itemType in malchecks[check]['checks']:
                self.sf.debug("Checking maliciousness of " + target + " (" +
                              itemType + ") with: " + cid)
                if malchecks[check]['type'] == "list":
                    return self.resourceList(cid, target, itemType)

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + ", already checked.")
            return None
        else:
            self.results.append(eventData)

        if eventName == 'CO_HOSTED_SITE' and not self.opts.get('checkcohosts', False):
            return None
        if eventName == 'AFFILIATE_INTERNET_NAME' \
                and not self.opts.get('checkaffiliates', False):
            return None

        for check in malchecks.keys():
            cid = malchecks[check]['id']
            # If the module is enabled..
            if self.opts[cid]:
                if eventName in ['INTERNET_NAME', 'CO_HOSTED_SITE', 'AFFILIATE_INTERNET_NAME' ]:
                    typeId = 'domain'
                    if eventName == "INTERNET_NAME":
                        evtType = "MALICIOUS_INTERNET_NAME"
                    if eventName == 'AFFILIATE_INTERNET_NAME':
                        evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
                    if eventName == 'CO_HOSTED_SITE':
                        evtType = 'MALICIOUS_COHOST'

                if self.checkForStop():
                    return None

                url = self.lookupItem(cid, typeId, eventData)
                # Notify other modules of what you've found
                if url is not None:
                    text = check + " [" + eventData + "]\n" + "<SFURL>" + url + "</SFURL>"
                    evt = SpiderFootEvent(evtType, text, self.__name__, event)
                    self.notifyListeners(evt)

        return None

# End of sfp_hostsfilenet class
