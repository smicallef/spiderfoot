#-------------------------------------------------------------------------------
# Name:         sfp_filemeta
# Purpose:      From Spidering and from searching search engines, extracts file
#               meta data from files matching certain file extensions.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import random
import re
import time
import urllib
import mimetypes
import metapdf
import pyPdf
import openxmllib
from StringIO import StringIO
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_filemeta(SpiderFootPlugin):
    """File Metadata:Extracts meta data from certain file types."""

    # Default options
    opts = {
        'fileexts':     [ "docx", "pptx", 'xlsx', 'pdf' ],
        'timeout':      300
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions of files you want to analyze the meta data of (only PDF, DOCX, XLSX and PPTX are supported.)",
        'timeout':  "Download timeout for files, in seconds."
    }

    results = list()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "LINKED_URL_INTERNAL", "INTERESTING_FILE" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "RAW_FILE_META_DATA" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        for fileExt in self.opts['fileexts']:
            if self.checkForStop():
                return None

            if "." + fileExt.lower() in eventData.lower():
                # Fetch the file, allow much more time given that these files are
                # typically large.
                ret = sf.fetchUrl(eventData, timeout=self.opts['timeout'], 
                    useragent=self.opts['_useragent'], dontMangle=True)
                if ret['content'] == None:
                    sf.error("Unable to fetch file for meta analysis: " + \
                        eventData, False)
                    return None

                if len(ret['content']) < 1024:
                    sf.error("Strange content encountered, size of " + \
                        len(res['content']), False)

                meta = None
                # Based on the file extension, handle it
                if fileExt.lower() == "pdf":
                    try:
                        data = StringIO(ret['content'])
                        meta = str(metapdf.MetaPdfReader().read_metadata(data))
                        sf.debug("Obtained meta data from " + eventData)
                    except BaseException as e:
                        sf.error("Unable to parse meta data from: " + \
                            eventData + "(" + str(e) + ")", False)
                        return None

                if fileExt.lower() in [ "pptx", "docx", "xlsx" ]:
                    try:
                        mtype = mimetypes.guess_type(eventData)[0]
                        doc = openxmllib.openXmlDocument(data=ret['content'], mime_type=mtype)
                        sf.debug("Office type: " + doc.mimeType)
                        meta = str(doc.allProperties)
                    except ValueError as e:
                        sf.error("Unable to parse meta data from: " + \
                            eventData + "(" + str(e) + ")", False)
                    except lxml.etree.XMLSyntaxError as e:
                        sf.error("Unable to parse XML within: " + \
                            eventData + "(" + str(e) + ")", False)

                if meta != None:
                    evt = SpiderFootEvent("RAW_FILE_META_DATA", meta,
                        self.__name__, event)
                    self.notifyListeners(evt)

                
# End of sfp_filemeta class
