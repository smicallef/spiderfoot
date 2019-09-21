# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_intfiles
# Purpose:      From Spidered pages found, identifies files of potential interest.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_intfiles(SpiderFootPlugin):
    """Interesting Files:Footprint:Crawling and Scanning::Identifies potential files of interest, e.g. office documents, zip files."""


    # Default options
    opts = {
        'fileexts': ["doc", "docx", "ppt", "pptx", "pdf", 'xls', 'xlsx', 'zip']
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions of files you consider interesting."
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERESTING_FILE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        for fileExt in self.opts['fileexts']:
            if "." + fileExt.lower() in eventData.lower():
                evt = SpiderFootEvent("INTERESTING_FILE", eventData,
                                      self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_intfiles class
