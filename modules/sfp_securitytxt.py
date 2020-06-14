# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_securitytxt
# Purpose:     Find and parse .well-known/security.txt files.
#
# Author:      Steve Bate <svc-spiderfoot@stevebate.net>
#
# Created:     14/06/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#
# See also:    https://tools.ietf.org/html/draft-foudil-securitytxt-09#page-7
# -------------------------------------------------------------------------------

from sflib import SpiderFootPlugin, SpiderFootEvent
from urllib.parse import urlparse, urlunparse
from securitytxt import SecurityTxt


class sfp_securitytxt(SpiderFootPlugin):
    """security.txt:Footprint:Crawling and Scanning::Retrieves and parses /.well-known/security.txt files"""

    opts = {
    }

    optdescs = {
    }

    def __init__(self):
        super().__init__()
        self.spiderfoot = None
        self.results = None

    def setup(self, spiderfoot, userOpts=None):
        self.spiderfoot = spiderfoot

        # self.tempStorage() basically returns a dict(), but we use self.tempStorage()
        # instead since on SpiderFoot HX, different mechanisms are used to persist
        # data for load distribution, avoiding excess memory consumption and fault
        # tolerance. This keeps modules transparently compatible with both versions.
        # Note that a new instance is created each time the function is called.
        self.results = self.tempStorage()

        if userOpts is not None:
            for opt in list(userOpts.keys()):
                self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["INTERNET_NAME", "DOMAINNAME"]

    # What events this module produces
    def producedEvents(self):
        return ["PGP_KEY", "EMAILADDR", "LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL"]

    def handleEvent(self, incomingEvent):
        self.spiderfoot.debug(f"Received event: {incomingEvent.eventType} from {incomingEvent.module}: {incomingEvent.data}")

        if incomingEvent.data in self.results:
            self.spiderfoot.debug(f"Skipping {incomingEvent.data}, already mapped.")
            return
        else:
            self.results[incomingEvent.data] = True

        for scheme in ['https', 'http']:
            url = f'{scheme}://{incomingEvent.data}/.well-known/security.txt'
            self.spiderfoot.debug(f'Attempting to retrieve {url}')

            try:
                response = self.spiderfoot.fetchUrl(url)
                if response['code'] == '200':
                    securitytxt = SecurityTxt(response['content'])
                    securitytxt.parse()
                    for contact in securitytxt.contact:
                        contactUrl = urlparse(contact)
                        if contactUrl.scheme in ['http', 'https']:
                            self._notifyLinkedUrl(incomingEvent, contactUrl)
                        elif contactUrl.scheme == 'mailto':
                            self._notifyEvent(incomingEvent, "EMAILADDR", contactUrl.path)
                    for encryption in securitytxt.encryption:
                        encryptionUrl = urlparse(encryption)
                        if encryptionUrl.scheme in ['http', 'https']:
                            encryptionResponse = self.spiderfoot.fetchUrl(encryption)
                            if encryptionResponse['code'] == '200':
                                self._notifyLinkedUrl(incomingEvent, encryptionUrl)
                                self._notifyEvent(incomingEvent, "PGP_KEY", encryptionResponse['content'])
                        else:
                            # TODO add support for DNS retrieval
                            self._notifyEvent(incomingEvent, "PGP_KEY", encryption)
                    break
            except BaseException as ex:
                # only logs to sferror.log
                self.spiderfoot.error("Failed to process security.txt", ex)
                # also fail the scan
                raise

    def _notifyLinkedUrl(self, incomingEvent, url):
        targetValue = self.getTarget().getValue()
        if targetValue in url.hostname or url.hostname in targetValue:
            outgoingEventType = "LINKED_URL_INTERNAL"
        else:
            outgoingEventType = "LINKED_URL_EXTERNAL"
        self._notifyEvent(incomingEvent, outgoingEventType, urlunparse(url))

    def _notifyEvent(self, incomingEvent, outgoingEventType, outgoingEventData):
        self.notifyListeners(SpiderFootEvent(
            outgoingEventType, outgoingEventData, type(self).__name__, incomingEvent))
