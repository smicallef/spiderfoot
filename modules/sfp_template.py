#-------------------------------------------------------------------------------
# Name:         sfp_XXX
# Purpose:      Template for plug-ins to use.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     02/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

# Replace XXX with the name of your module. The comment below it will
# end up in the UI as the module description to the end-user.
class sfp_XXX(SpiderFootPlugin):
    """About me here.."""

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
    baseDomain = None
    results = dict() # track results for duplicates

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["RAW_DATA"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventSourceEvent, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities.

# End of sfp_XXX class
