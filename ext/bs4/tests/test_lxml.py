"""Tests to ensure that the lxml tree builder generates good trees."""

import re
import warnings

try:
    import lxml.etree
    LXML_PRESENT = True
    LXML_VERSION = lxml.etree.LXML_VERSION
except ImportError, e:
    LXML_PRESENT = False
    LXML_VERSION = (0,)

if LXML_PRESENT:
    from bs4.builder import LXMLTreeBuilder, LXMLTreeBuilderForXML

from bs4 import (
    BeautifulSoup,
    BeautifulStoneSoup,
    )
from bs4.element import Comment, Doctype, SoupStrainer
from bs4.testing import skipIf
from bs4.tests import test_htmlparser
from bs4.testing import (
    HTMLTreeBuilderSmokeTest,
    XMLTreeBuilderSmokeTest,
    SoupTest,
    skipIf,
)

@skipIf(
    not LXML_PRESENT,
    "lxml seems not to be present, not testing its tree builder.")
class LXMLTreeBuilderSmokeTest(SoupTest, HTMLTreeBuilderSmokeTest):
    """See ``HTMLTreeBuilderSmokeTest``."""

    @property
    def default_builder(self):
        return LXMLTreeBuilder()

    def test_out_of_range_entity(self):
        self.assertSoupEquals(
            "<p>foo&#10000000000000;bar</p>", "<p>foobar</p>")
        self.assertSoupEquals(
            "<p>foo&#x10000000000000;bar</p>", "<p>foobar</p>")
        self.assertSoupEquals(
            "<p>foo&#1000000000;bar</p>", "<p>foobar</p>")

    # In lxml < 2.3.5, an empty doctype causes a segfault. Skip this
    # test if an old version of lxml is installed.

    @skipIf(
        not LXML_PRESENT or LXML_VERSION < (2,3,5,0),
        "Skipping doctype test for old version of lxml to avoid segfault.")
    def test_empty_doctype(self):
        soup = self.soup("<!DOCTYPE>")
        doctype = soup.contents[0]
        self.assertEqual("", doctype.strip())

    def test_beautifulstonesoup_is_xml_parser(self):
        # Make sure that the deprecated BSS class uses an xml builder
        # if one is installed.
        with warnings.catch_warnings(record=True) as w:
            soup = BeautifulStoneSoup("<b />")
        self.assertEqual(u"<b/>", unicode(soup.b))
        self.assertTrue("BeautifulStoneSoup class is deprecated" in str(w[0].message))

@skipIf(
    not LXML_PRESENT,
    "lxml seems not to be present, not testing its XML tree builder.")
class LXMLXMLTreeBuilderSmokeTest(SoupTest, XMLTreeBuilderSmokeTest):
    """See ``HTMLTreeBuilderSmokeTest``."""

    @property
    def default_builder(self):
        return LXMLTreeBuilderForXML()
