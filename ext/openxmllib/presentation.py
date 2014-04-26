# -*- coding: utf-8 -*-
"""
The presentation module handles a PresentationML Open XML document (read *.pptx)
"""
# $Id: presentation.py 6800 2007-12-04 11:17:01Z glenfant $

import document
from utils import IndexableTextExtractor
import contenttypes as ct
import namespaces

class PresentationDocument(document.Document):
    """Handles specific features of a PresentationML document
    """
    _extpattern_to_mime = {
        '*.pptx': ct.CT_PRESENTATION_PPTX_PUBLIC,
        '*.pptm': ct.CT_PRESENTATION_PPTM_PUBLIC,
        '*.potx': ct.CT_PRESENTATION_POTX_PUBLIC,
        '*.potm': ct.CT_PRESENTATION_POTM_PUBLIC,
        '*.ppsx': ct.CT_PRESENTATION_PPSX_PUBLIC,
        '*.ppsm': ct.CT_PRESENTATION_PPSM_PUBLIC,
        # FIXME: Not sure we can honour below types
#        '*.ppam': ct.CT_PRESENTATION_PPAM_PUBLIC
        }

    _text_extractors = (
        IndexableTextExtractor(ct.CT_PRESENTATION_SLIDE, 'presentation-main:t', separator=' '),
        )

    def textFromTree(self, tree):
        for text in tree.xpath('//presentation-main:t/text()', namespaces=namespaces.ns_map):
            yield ''.join(t.encode('utf-8') for t in text)

