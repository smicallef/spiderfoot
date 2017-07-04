# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_db
# Purpose:      SpiderFoot plug-in for storing events to the local SpiderFoot
#               SQLite database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin


class sfp__stor_db(SpiderFootPlugin):
    """Storage::::Stores scan results into the back-end SpiderFoot database. You will need this."""

    # Default options
    opts = {
        'maxstorage': 1024  # max bytes for any piece of info stored (0 = unlimited)
    }

    # Option descriptions
    optdescs = {
        'maxstorage': "Maximum bytes to store for any piece of information retreived (0 = unlimited.)"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # Because this is a storage plugin, we are interested in everything so we
    # can store all events for later analysis.
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, sfEvent):
        if self.opts['maxstorage'] != 0:
            if len(sfEvent.data) > self.opts['maxstorage']:
                self.sf.debug("Storing an event: " + sfEvent.eventType)
                self.__sfdb__.scanEventStore(self.getScanId(), sfEvent, self.opts['maxstorage'])
                return None

        self.sf.debug("Storing an event: " + sfEvent.eventType)
        self.__sfdb__.scanEventStore(self.getScanId(), sfEvent)


# End of sfp__stor_db class
