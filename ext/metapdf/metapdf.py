#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012 Ali Anari
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
.. module:: metapdf
   :platform: Unix, Windows
   :synopsis: The metapdf class implementation.

.. moduleauthor:: Ali Anari <ali@alianari.com>

"""

__author__ = "Ali Anari"
__author_email__ = "ali@alianari.com"


import os, re
from pyPdf import PdfFileReader


class _meta_pdf_reader(object):

    def __init__(self):
        self.instance = self.__hash__()
        self.metadata_regex = re.compile('(?:\/(\w+)\s?\(([^\n\r]*)\)\n?\r?)', re.S)
        self.metadata_offset = 2048

    def read_metadata(self, stream):

        """This function reads a PDF file stream and returns its metadata.
        :param file_name: The PDF file stream to read.
        :type file_name: str
        :returns: dict -- The returned metadata as a dictionary of properties.

        """

        # Scan the last 2048 bytes, the most
        # frequent metadata density block
        stream.seek(-self.metadata_offset, os.SEEK_END)
        properties = dict()
        try:
            properties = dict(('/' + p.group(1), p.group(2).decode('utf-8')) \
                for p in self.metadata_regex.finditer(stream.read(self.metadata_offset)))
            if '/Author' in properties:
                return properties
        except UnicodeDecodeError:
            properties.clear()

        # Parse the xref table using pyPdf
        properties = PdfFileReader(stream).documentInfo
        if properties:
            return properties

        return {}

_metaPdfReader = _meta_pdf_reader()
def MetaPdfReader(): return _metaPdfReader
