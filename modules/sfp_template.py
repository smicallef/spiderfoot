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

class sfp_XXX(SpiderFootPlugin):
    """About me here.."""

    # Default options
    opts = {
        # These must always be set
        '__debug':       True,
        '__debugfilter': ''
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in setup
    results = dict() # track results for duplicates

    def setup(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

         # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBCONTENT"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities.

# End of sfp_XXX class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
