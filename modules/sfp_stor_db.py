#-------------------------------------------------------------------------------
# Name:         sfp_stor_db
# Purpose:      SpiderFoot plug-in for storing events to the local SpiderFoot
#               SQLite database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None
sfdb = None

class sfp_stor_db(SpiderFootPlugin):
    """Stores scan results into the back-end SpiderFoot database. You will need this."""

    # Default options
    opts = {
        'maxstorage':   1024 # max bytes for any piece of info stored (0 = unlimited)
    }

    # Option descriptions
    optdescs = {
        'maxstorage':   "Maximum bytes to store for any piece of information retreived."
    }

    # URL this instance is working on
    seedUrl = None

    def setup(self, sfc, url, userOpts=dict()):
        global sf
        global sfdb

        sf = sfc
        self.seedUrl = url

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # Use the database handle passed to us
        sfdb = userOpts['__sfdb__']

    # What events is this module interested in for input
    # Because this is a storage plugin, we are interested in everything so we
    # can store all events for later analysis.
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        # Convert to a string in case we get passed integers or other things
        eventData = str(eventData)
        if self.opts['maxstorage'] != 0:
            if len(eventData) > self.opts['maxstorage']:
                sf.debug("Truncated " + eventName + " data due to storage limitation")
                sfdb.scanEventStore(self.opts['__guid__'], eventName, eventSource,
                    eventData[0:self.opts['maxstorage']], srcModuleName)
                return None
        
        sfdb.scanEventStore(self.opts['__guid__'], eventName, eventSource,
            eventData, srcModuleName)


# End of sfp_stor_db class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
