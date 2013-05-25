#-------------------------------------------------------------------------------
# Name:         sfp_XXX
# Purpose:      Description of the plug-in.
#
# Author:      Name and e-mail address
#
# Created:     Date
# Copyright:   (c) Name
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_XXX(SpiderFootPlugin):
    """Description"""

    # Default options
    opts = { }

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    # Target
    baseDomain = None # calculated from the URL in setup
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        # If you are processing RAW_DATA from sfp_spider, this is how you 
        # would get the source of that raw data (e.g. a URL.)
        eventSource = event.sourceEvent.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

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
