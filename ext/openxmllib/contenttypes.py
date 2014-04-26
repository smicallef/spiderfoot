# -*- coding: utf-8 -*-
"""
The various inner content types in an open XML document
"""
# $Id: contenttypes.py 6800 2007-12-04 11:17:01Z glenfant $

import os
from lxml import etree
import namespaces as ns
import utils

# Common properties
CT_CORE_PROPS = 'application/vnd.openxmlformats-package.core-properties+xml'
CT_EXT_PROPS = 'application/vnd.openxmlformats-officedocument.extended-properties+xml'
CT_CUSTOM_PROPS = 'application/vnd.openxmlformats-officedocument.custom-properties+xml'

# Wordprocessing document
# See...
# http://technet2.microsoft.com/Office/en-us/library/e077da98-0216-45eb-b6a7-957f9c510a851033.mspx?pf=true
# ...for the various
CT_WORDPROC_DOCX_PUBLIC = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
CT_WORDPROC_DOTX_PUBLIC = 'application/vnd.openxmlformats-officedocument.wordprocessingml.template'
CT_WORDPROC_DOCM_PUBLIC = 'application/vnd.ms-word.document.macroEnabled.12'
CT_WORDPROC_DOTM_PUBLIC = 'application/vnd.ms-word.template.macroEnabled.12'

CT_WORDPROC_DOCUMENT = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
CT_WORDPROC_NUMBERING = 'application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml'
CT_WORDPROC_STYPES = 'application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml'
CT_WORDPROC_FONTS = 'application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml'
CT_WORDPROC_SETINGS = 'application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml'
CT_WORDPROC_FOOTNOTES = 'application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml'
CT_WORDPROC_ENDNOTES = 'application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml'
CT_WORDPROC_COMMENTS = 'application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml'

# Presentation document
CT_PRESENTATION_PPTX_PUBLIC = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
CT_PRESENTATION_PPTM_PUBLIC = 'application/vnd.ms-powerpoint.presentation.macroEnabled.12'
CT_PRESENTATION_PPSX_PUBLIC = 'application/vnd.openxmlformats-officedocument.presentationml.slideshow'
CT_PRESENTATION_PPSM_PUBLIC = 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12'
CT_PRESENTATION_PPAM_PUBLIC = 'application/vnd.ms-powerpoint.addin.macroEnabled.12'
CT_PRESENTATION_POTX_PUBLIC = 'application/vnd.openxmlformats-officedocument.presentationml.template'
CT_PRESENTATION_POTM_PUBLIC = 'application/vnd.ms-powerpoint.template.macroEnabled.12'

# FIXME: Other presentation inner content types but useless for now...
CT_PRESENTATION_SLIDE = 'application/vnd.openxmlformats-officedocument.presentationml.slide+xml'

# Spreadsheet document
CT_SPREADSHEET_XLAM_PUBLIC = 'application/vnd.ms-excel.addin.macroEnabled.12'
CT_SPREADSHEET_XLSB_PUBLIC = 'application/vnd.ms-excel.sheet.binary.macroEnabled.12'
CT_SPREADSHEET_XLSM_PUBLIC = 'application/vnd.ms-excel.sheet.macroEnabled.12'
CT_SPREADSHEET_XLSX_PUBLIC = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
CT_SPREADSHEET_XLTM_PUBLIC = 'application/vnd.ms-excel.template.macroEnabled.12'
CT_SPREADSHEET_XLTX_PUBLIC = 'application/vnd.openxmlformats-officedocument.spreadsheetml.template'

# FIXME: Other spreadsheet inner content types but useless for now...
CT_SPREADSHEET_WORKSHEET = 'application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml'
CT_SPREADSHEET_SHAREDSTRINGS = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml'


class ContentTypes(object):
    """Handles features from the [Content_Types].xml file"""

    def __init__(self, content_types_file):
        """Constructor
        @param content_types_file: a file like object of [Content_Types].xml
        """

        self.overrides = {} # {subpart content type: [xml file, ...], ...}
        context = etree.iterparse(content_types_file, tag='{%s}Override' % ns.CONTENT_TYPES)
        for dummy, override in context:
            key = override.get('ContentType')
            if self.overrides.has_key(key):
                self.overrides[key].append(override.get('PartName'))
            else:
                self.overrides[key] = [override.get('PartName')]
        return


    def getPathsForContentType(self, content_type):
        """Finds the path in the document to that content type
        @param content_type: a MIME content type
        @return: list of paths in the content type
        """

        return self.overrides.get(content_type, [])


    def getTreesFor(self, document, content_type):
        """Provides all XML documents for that content type
        @param document: a Document or subclass object
        @param content_type: a MIME content type
        @return: list of etree._ElementTree of that content type
        """

        # Relative path without potential leading path separator
        # otherwise os.path.join doesn't work
        for rel_path in self.overrides[content_type]:
            if rel_path[0] in ('/', '\\'):
                rel_path = rel_path[1:]
            file_path = os.path.join(document._cache_dir, rel_path)
            yield etree.parse(utils.xmlFile(file_path, 'rb'))
        return


    @property
    def listMetaContentTypes(self):
        """The content types with metadata
        @return: ['application/xxx', ...]
        """

        all_md_content_types = (
            CT_CORE_PROPS,
            CT_EXT_PROPS,
            CT_CUSTOM_PROPS)
        return [k for k in self.overrides.keys() if k in all_md_content_types]

