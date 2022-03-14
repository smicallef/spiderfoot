# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_filemeta
# Purpose:      From Spidering and from searching search engines, extracts file
#               meta data from files matching certain file extensions.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import io
import mimetypes

import PyPDF2

import docx

import exifread

import pptx

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_filemeta(SpiderFootPlugin):

    meta = {
        'name': "File Metadata Extractor",
        'summary': "Extracts meta data from documents and images.",
        'flags': [],
        'useCases': ["Footprint"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
        'fileexts': ["docx", "pptx", 'pdf', 'jpg', 'jpeg', 'tiff', 'tif'],
        'timeout': 300
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions of files you want to analyze the meta data of (only PDF, DOCX, XLSX and PPTX are supported.)",
        'timeout': "Download timeout for files, in seconds."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "INTERESTING_FILE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_FILE_META_DATA", "SOFTWARE_USED"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        for fileExt in self.opts['fileexts']:
            if self.checkForStop():
                return

            if "." + fileExt.lower() in eventData.lower():
                # Fetch the file, allow much more time given that these files are
                # typically large.
                ret = self.sf.fetchUrl(eventData, timeout=self.opts['timeout'],
                                       useragent=self.opts['_useragent'], disableContentEncoding=True,
                                       sizeLimit=10000000,
                                       verify=False)
                if ret['content'] is None:
                    self.error(f"Unable to fetch file for meta analysis: {eventData}")
                    return

                if len(ret['content']) < 512:
                    self.error(f"Strange content encountered, size of {len(ret['content'])}")
                    return

                meta = None
                data = None
                # Based on the file extension, handle it
                if fileExt.lower() == "pdf":
                    try:
                        raw = io.BytesIO(ret['content'])
                        # data = metapdf.MetaPdfReader().read_metadata(raw)
                        pdf = PyPDF2.PdfFileReader(raw, strict=False)
                        data = pdf.getDocumentInfo()
                        meta = str(data)
                        self.debug("Obtained meta data from " + eventData)
                    except Exception as e:
                        self.error(f"Unable to parse meta data from: {eventData} ({e})")
                        return

                if fileExt.lower() in ["docx"]:
                    try:
                        c = io.BytesIO(ret['content'])
                        doc = docx.Document(c)
                        mtype = mimetypes.guess_type(eventData)[0]
                        self.debug("Office type: " + str(mtype))
                        a = doc.core_properties.author
                        c = doc.core_properties.comments
                        data = [_f for _f in [a, c] if _f]
                        meta = ", ".join(data)
                    except Exception as e:
                        self.error(f"Unable to process file: {eventData} ({e})")
                        return

                if fileExt.lower() in ["pptx"]:
                    try:
                        c = io.BytesIO(ret['content'])
                        doc = pptx.Presentation(c)
                        mtype = mimetypes.guess_type(eventData)[0]
                        self.debug("Office type: " + str(mtype))
                        a = doc.core_properties.author
                        c = doc.core_properties.comments
                        data = [_f for _f in [a, c] if _f]
                        meta = ", ".join(data)
                    except Exception as e:
                        self.error(f"Unable to process file: {eventData} ({e})")
                        return

                if fileExt.lower() in ["jpg", "jpeg", "tiff"]:
                    try:
                        raw = io.BytesIO(ret['content'])
                        data = exifread.process_file(raw)
                        if data is None or len(data) == 0:
                            continue
                        meta = str(data)
                    except Exception as e:
                        self.error(f"Unable to parse meta data from: {eventData} ({e})")
                        return

                if meta is not None and data is not None:
                    rawevt = SpiderFootEvent("RAW_FILE_META_DATA", meta,
                                             self.__name__, event)
                    self.notifyListeners(rawevt)

                    val = list()
                    try:
                        if "/Producer" in data:
                            val.append(str(data['/Producer']))

                        if "/Creator" in data:
                            val.append(str(data['/Creator']))

                        if "Application" in data:
                            val.append(str(data['Application']))

                        if "Image Software" in data:
                            val.append(str(data['Image Software']))
                    except Exception as e:
                        self.error("Failed to parse PDF, " + eventData + ": " + str(e))
                        return

                    for v in val:
                        if v and not isinstance(v, PyPDF2.generic.NullObject):
                            self.debug("VAL: " + str(val))
                            # Strip non-ASCII
                            v = ''.join([i if ord(i) < 128 else ' ' for i in v])
                            evt = SpiderFootEvent("SOFTWARE_USED", v, self.__name__, rawevt)
                            self.notifyListeners(evt)
