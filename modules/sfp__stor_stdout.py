# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_stdout
# Purpose:      SpiderFoot plug-in for dumping events to standard output.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/10/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin
import json


class sfp__stor_stdout(SpiderFootPlugin):
    """Command-line output::::Dumps output to standard out. Used for when a SpiderFoot scan is run via the command-line."""

    # Default options
    opts = {
        "_format": "tab", # tab, csv, json
        "_requested": [],
        "_showonlyrequested": False,
        "_stripnewline": False,
        "_showsource": False,
        "_csvdelim": ",",
        "_maxlength": 0,
        "_eventtypes": dict()
    }

    # Option descriptions
    optdescs = {
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

    def output(self, event):
        d = self.opts['_csvdelim']
        if type(event.data) in [list, dict]:
            data = unicode(str(event.data), 'utf-8', errors='replace')
        else:
            data = event.data

        if type(data) != unicode:
            data = unicode(event.data, 'utf-8', errors='replace')

        if type(event.sourceEvent.data) in [list, dict]:
            srcdata = unicode(str(event.sourceEvent.data), 'utf-8', errors='replace')
        else:
            srcdata = event.sourceEvent.data

        if type(srcdata) != unicode:
            srcdata = unicode(event.sourceEvent.data, 'utf-8', errors='replace')

        if self.opts['_stripnewline']:
            data = data.replace("\n", "").replace("\r", "")
            srcdata = srcdata.replace("\n", "").replace("\r", "")

        if self.opts['_maxlength'] > 0:
            data = data[0:self.opts['_maxlength']]
            srcdata = srcdata[0:self.opts['_maxlength']]

        if self.opts['_format'] == "tab":
            if self.opts['_showsource']:
                print('{0:30}\t{1:45}\t{2}\t{3}'.format(event.module, self.opts['_eventtypes'][event.eventType], srcdata, data))
            else:
                print('{0:30}\t{1:45}\t{2}'.format(event.module, self.opts['_eventtypes'][event.eventType], data))

        if self.opts['_format'] == "csv":
            print(event.module + d + self.opts['_eventtypes'][event.eventType] + d + srcdata + d + data)

        if self.opts['_format'] == "json":
            d = event.asDict()
            d['type'] = self.opts['_eventtypes'][event.eventType]
            print(json.dumps(d))


    # Handle events sent to this module
    def handleEvent(self, sfEvent):
        if sfEvent.eventType == "ROOT":
            return None

        if self.opts['_showonlyrequested']:
            if sfEvent.eventType in self.opts['_requested']:
                self.output(sfEvent)
        else:
            self.output(sfEvent)

# End of sfp__stor_stdout class
