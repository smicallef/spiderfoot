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

# SpiderFoot standard lib (must be initialized in __init__)
sf = None
sfdb = None

class sfp_stor_db(SpiderFootPlugin):
    # Default options
    opts = {
        # These must always be set
        '_debug':       True,
        '_debugfilter': ''
    }

    # URL this instance is working on
    seedUrl = None

    def __init__(self, url, userOpts=dict()):
        global sf
        global sfdb
        self.seedUrl = url

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)
        # Use the database handle passed to us
        sfdb = userOpts['__sfdb__']

    # What events is this module interested in for input
    # Because this is a storage plugin, we are interested in everything so we
    # can store all events for later analysis.
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sfdb.scanEventStore(self.opts['__guid__'], eventName, eventSource,
            eventData, srcModuleName)

# End of sfp_stor_db class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
