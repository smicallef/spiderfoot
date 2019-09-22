# coding: utf-8
# -------------------------------------------------------------------------------
# Name:         sfp_binstring
# Purpose:      Identify strings in binary content.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/12/2016
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import string
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_binstring(SpiderFootPlugin):
    """Binary String Extractor:Footprint:Content Analysis:errorprone:Attempt to identify strings in binary content."""


    # Default options
    opts = {
        'minwordsize': 5,
        'maxwords': 100,
        'maxfilesize': 1000000,
        'usedict': True,
        'fileexts': ['png', 'gif', 'jpg', 'jpeg', 'tiff', 'tif',
                    'ico', 'flv', 'mp4', 'mp3', 'avi', 'mpg',
                    'mpeg', 'dat', 'mov', 'swf', 'exe', 'bin'],
        'filterchars': '#}{|%^&*()=+,;[]~'
    }

    # Option descriptions
    optdescs = {
        'minwordsize': "Upon finding a string in a binary, ensure it is at least this length. Helps weed out false positives.",
        'usedict': "Use the dictionary to further reduce false positives - any string found must contain a word from the dictionary (can be very slow, especially for larger files).",
        'fileexts': "File types to fetch and analyse.",
        'maxfilesize': "Maximum file size in bytes to download for analysis.",
        'maxwords': "Stop reporting strings from a single binary after this many are found.",
        'filterchars': "Ignore strings with these characters, as they may just be garbage ASCII."
    }

    results = list()
    d = None
    n = None
    fq = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()
        self.__dataSource__ = "Target Website"

        self.d = set(self.sf.dictwords())

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def getStrings(self, content):
        words = list()
        result = ""

        if not content:
            return None

        for c in content:
            if len(words) >= self.opts['maxwords']:
                break
            if c in string.printable and c not in string.whitespace:
                result += c
                continue
            if len(result) >= self.opts['minwordsize']:
                if self.opts['usedict']:
                    accept = False
                    for w in self.d:
                        if result.startswith(w) or result.endswith(w):
                            accept = True
                            break

                if self.opts['filterchars']:
                    accept = True
                    for x in self.opts['filterchars']:
                        if x in result:
                            accept = False
                            break

                if not self.opts['filterchars'] and not self.opts['usedict']:
                    accept = True

                if accept:
                    words.append(result)
                    
                result = ""

        if len(words) == 0:
            return None

        return words

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_FILE_META_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        # if the file matches any of the file extensions we are interested in
        # then fetch the file and write it to aa temporary place
        res = None
        for fileExt in self.opts['fileexts']:
            if eventData.lower().endswith("." + fileExt.lower()) or "." + fileExt + "?" in eventData.lower():
                res = self.sf.fetchUrl(eventData, 
                                       useragent=self.opts['_useragent'], 
                                       dontMangle=True,
                                       sizeLimit=self.opts['maxfilesize'])
                
        if res:
            self.sf.debug("Searching for strings")
            words = self.getStrings(res['content'])

            if words:
                wordstr = '\n'.join(words[0:self.opts['maxwords']])

                # Notify other modules of what you've found
                evt = SpiderFootEvent("RAW_FILE_META_DATA", wordstr, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_binstring class
