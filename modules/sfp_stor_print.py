# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_print
# Purpose:      SpiderFoot plug-in for 'storing' events (by printing them to
#               the screen. This is used for debugging.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin


class sfp_stor_print(SpiderFootPlugin):
    # Default options
    opts = {
        'datasize': 100  # Number of characters to print from event data
    }

    # Option descriptions
    optdescs = {
        "datasize": "Maximum number of bytes to print on the screen for debug."
    }

    def __init__(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Module description
    def descr(self):
        return "Debugging module for printing results instead of storing them."

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventSourceEvent, eventData):
        self.sf.debug("RESULT:")
        self.sf.debug("\tSource: " + srcModuleName)
        self.sf.debug("\tEvent: " + eventName)
        self.sf.debug("\tEvent Source: " + eventSource)
        if len(eventData) > self.opts['datasize']:
            eventDataStripped = eventData[0:self.opts['datasize']] + '...'
        else:
            eventDataStripped = eventData
        self.sf.debug("\tEvent Data: " + eventDataStripped)

        return None

# End of sfp_stor_print class
