# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_XXX
# Purpose:      Description of the plug-in.
#
# Author:      Name and e-mail address
#
# Created:     Date
# Copyright:   (c) Name
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_XXX(SpiderFootPlugin):
    """Name:Use Cases:Category:Labels:Description"""

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    # Target
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["*"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        # If you are processing TARGET_WEB_CONTENT from sfp_spider, this is how you 
        # would get the source of that raw data (e.g. a URL.)
        eventSource = event.sourceEvent.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # DO SOMETHING HERE

        # Notify other modules of what you've found
        evt = SpiderFootEvent("EVENT_CODE_HERE", "data here", self.__name__, event.sourceEvent)
        self.notifyListeners(evt)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities (user abort.)

# End of sfp_XXX class
