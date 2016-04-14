# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_passivetotal
# Purpose:      Performs lookups against the PassiveTotal API
#
# Author:      Johan Nestaas <johan.nestaas@riskiq.net>
#
# Created:     04/14/2016
# Copyright:   (c) RiskIQ
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import (
    # SpiderFoot,
    SpiderFootPlugin,
    SpiderFootEvent,
)


class sfp_passivetotal(SpiderFootPlugin):
    '''passivetotal:footprint:Performs lookups against the PassiveTotal API'''

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {
    }

    # Target
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        ''' Performs setup of the module '''
        self.sf = sfc
        self.results = dict()

        # Clear out options so data won't persist.
        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        '''
        The events this module is interested in for input, * being all events.
        '''
        return ["*"]

    def producedEvents(self):
        '''
        The events this module produces, to help the end user in selecting
        modules.
        '''
        return None

    def handleEvent(self, event):
        ''' Handle events sent to the module '''
        eventName = event.eventType
        srcModuleName = event.module
        # eventData = event.data
        # If you are processing TARGET_WEB_CONTENT from sfp_spider, this is how
        # you would get the source of that raw data (e.g. a URL.)
        # eventSource = event.sourceEvent.data

        self.sf.debug("Received event, " + eventName + ", from " +
                      srcModuleName)

        # DO SOMETHING HERE

        # Notify other modules of what you've found
        evt = SpiderFootEvent("EVENT_CODE_HERE", "data here", self.__name__,
                              event.sourceEvent)
        self.notifyListeners(evt)

        return None

    def start(self):
        ''' Defined so that it doesn't depend on other modules for events '''
        while True:
            # User aborted scan.
            if self.checkForStop():
                break

# End of sfp_passivetotal class
