# -*- coding: utf-8 -*-
"""
The spreadsheet module handles a SpreadsheetML Open XML document (read *.xlsx)
"""
# $Id: spreadsheet.py 6800 2007-12-04 11:17:01Z glenfant $

import document
from utils import IndexableTextExtractor
import contenttypes as ct
import namespaces


class SpreadsheetDocument(document.Document):
    """Handles specific features of a SpreadsheetML document
    """
    _extpattern_to_mime = {
        '*.xlsx': ct.CT_SPREADSHEET_XLSX_PUBLIC,
        '*.xlsm': ct.CT_SPREADSHEET_XLSM_PUBLIC,
        '*.xltx': ct.CT_SPREADSHEET_XLTX_PUBLIC,
        '*.xltm': ct.CT_SPREADSHEET_XLTM_PUBLIC,
        # FIXME: note sure we can honour below types...
#        '*.xlam': ct.CT_SPREADSHEET_XLAM_PUBLIC,
#        '*.xlsb': ct.CT_SPREADSHEET_XLSB_PUBLIC
        }

    _text_extractors = (
        IndexableTextExtractor(ct.CT_SPREADSHEET_SHAREDSTRINGS, 'spreadsheet-main:t', separator=' '),
        )


    def textFromTree(self, tree):

        for text in tree.xpath('//spreadsheet-main:t/text()', namespaces=namespaces.ns_map):
            yield ''.join(t.encode('utf-8') for t in text)

