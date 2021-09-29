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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_binstring(SpiderFootPlugin):

    meta = {
        'name': "Binary String Extractor",
        'summary': "Attempt to identify strings in binary content.",
        'flags': ["errorprone"],
        'useCases': ["Footprint"],
        'categories': ["Content Analysis"]
    }

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

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def getStrings(self, content):
        words = list()
        result = ""

        if not content:
            return None

        for c in content:
            c = str(c)
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
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_FILE_META_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results.append(eventData)

        for fileExt in self.opts['fileexts']:
            if eventData.lower().endswith(f".{fileExt.lower()}") or f".{fileExt.lower()}?" in eventData.lower():
                res = self.sf.fetchUrl(
                    eventData,
                    useragent=self.opts['_useragent'],
                    disableContentEncoding=True,
                    sizeLimit=self.opts['maxfilesize'],
                    verify=False
                )

                if not res:
                    continue

                self.debug(f"Searching {eventData} for strings")
                words = self.getStrings(res['content'])

                if words:
                    wordstr = '\n'.join(words[0:self.opts['maxwords']])
                    evt = SpiderFootEvent("RAW_FILE_META_DATA", wordstr, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_binstring class
