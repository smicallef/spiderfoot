# -*- coding: utf-8 -*-
"""Tests of Beautiful Soup as a whole."""

from pdb import set_trace
import logging
import unittest
import sys
import tempfile

from bs4 import (
    BeautifulSoup,
    BeautifulStoneSoup,
)
from bs4.element import (
    CharsetMetaAttributeValue,
    ContentMetaAttributeValue,
    SoupStrainer,
    NamespacedAttribute,
    )
import bs4.dammit
from bs4.dammit import (
    EntitySubstitution,
    UnicodeDammit,
    EncodingDetector,
)
from bs4.testing import (
    SoupTest,
    skipIf,
)
import warnings

try:
    from bs4.builder import LXMLTreeBuilder, LXMLTreeBuilderForXML
    LXML_PRESENT = True
except ImportError, e:
    LXML_PRESENT = False

PYTHON_2_PRE_2_7 = (sys.version_info < (2,7))
PYTHON_3_PRE_3_2 = (sys.version_info[0] == 3 and sys.version_info < (3,2))

class TestConstructor(SoupTest):

    def test_short_unicode_input(self):
        data = u"<h1>éé</h1>"
        soup = self.soup(data)
        self.assertEqual(u"éé", soup.h1.string)

    def test_embedded_null(self):
        data = u"<h1>foo\0bar</h1>"
        soup = self.soup(data)
        self.assertEqual(u"foo\0bar", soup.h1.string)

    def test_exclude_encodings(self):
        utf8_data = u"Räksmörgås".encode("utf-8")
        soup = self.soup(utf8_data, exclude_encodings=["utf-8"])
        self.assertEqual("windows-1252", soup.original_encoding)


class TestWarnings(SoupTest):

    def _no_parser_specified(self, s, is_there=True):
        v = s.startswith(BeautifulSoup.NO_PARSER_SPECIFIED_WARNING[:80])
        self.assertTrue(v)

    def test_warning_if_no_parser_specified(self):
        with warnings.catch_warnings(record=True) as w:
            soup = self.soup("<a><b></b></a>")
        msg = str(w[0].message)
        self._assert_no_parser_specified(msg)

    def test_warning_if_parser_specified_too_vague(self):
        with warnings.catch_warnings(record=True) as w:
            soup = self.soup("<a><b></b></a>", "html")
        msg = str(w[0].message)
        self._assert_no_parser_specified(msg)

    def test_no_warning_if_explicit_parser_specified(self):
        with warnings.catch_warnings(record=True) as w:
            soup = self.soup("<a><b></b></a>", "html.parser")
        self.assertEquals([], w)

    def test_parseOnlyThese_renamed_to_parse_only(self):
        with warnings.catch_warnings(record=True) as w:
            soup = self.soup("<a><b></b></a>", parseOnlyThese=SoupStrainer("b"))
        msg = str(w[0].message)
        self.assertTrue("parseOnlyThese" in msg)
        self.assertTrue("parse_only" in msg)
        self.assertEqual(b"<b></b>", soup.encode())

    def test_fromEncoding_renamed_to_from_encoding(self):
        with warnings.catch_warnings(record=True) as w:
            utf8 = b"\xc3\xa9"
            soup = self.soup(utf8, fromEncoding="utf8")
        msg = str(w[0].message)
        self.assertTrue("fromEncoding" in msg)
        self.assertTrue("from_encoding" in msg)
        self.assertEqual("utf8", soup.original_encoding)

    def test_unrecognized_keyword_argument(self):
        self.assertRaises(
            TypeError, self.soup, "<a>", no_such_argument=True)

class TestWarnings(SoupTest):

    def test_disk_file_warning(self):
        filehandle = tempfile.NamedTemporaryFile()
        filename = filehandle.name
        try:
            with warnings.catch_warnings(record=True) as w:
                soup = self.soup(filename)
            msg = str(w[0].message)
            self.assertTrue("looks like a filename" in msg)
        finally:
            filehandle.close()

        # The file no longer exists, so Beautiful Soup will no longer issue the warning.
        with warnings.catch_warnings(record=True) as w:
            soup = self.soup(filename)
        self.assertEqual(0, len(w))

    def test_url_warning(self):
        with warnings.catch_warnings(record=True) as w:
            soup = self.soup("http://www.crummy.com/")
        msg = str(w[0].message)
        self.assertTrue("looks like a URL" in msg)

        with warnings.catch_warnings(record=True) as w:
            soup = self.soup("http://www.crummy.com/ is great")
        self.assertEqual(0, len(w))

class TestSelectiveParsing(SoupTest):

    def test_parse_with_soupstrainer(self):
        markup = "No<b>Yes</b><a>No<b>Yes <c>Yes</c></b>"
        strainer = SoupStrainer("b")
        soup = self.soup(markup, parse_only=strainer)
        self.assertEqual(soup.encode(), b"<b>Yes</b><b>Yes <c>Yes</c></b>")


class TestEntitySubstitution(unittest.TestCase):
    """Standalone tests of the EntitySubstitution class."""
    def setUp(self):
        self.sub = EntitySubstitution

    def test_simple_html_substitution(self):
        # Unicode characters corresponding to named HTML entites
        # are substituted, and no others.
        s = u"foo\u2200\N{SNOWMAN}\u00f5bar"
        self.assertEqual(self.sub.substitute_html(s),
                          u"foo&forall;\N{SNOWMAN}&otilde;bar")

    def test_smart_quote_substitution(self):
        # MS smart quotes are a common source of frustration, so we
        # give them a special test.
        quotes = b"\x91\x92foo\x93\x94"
        dammit = UnicodeDammit(quotes)
        self.assertEqual(self.sub.substitute_html(dammit.markup),
                          "&lsquo;&rsquo;foo&ldquo;&rdquo;")

    def test_xml_converstion_includes_no_quotes_if_make_quoted_attribute_is_false(self):
        s = 'Welcome to "my bar"'
        self.assertEqual(self.sub.substitute_xml(s, False), s)

    def test_xml_attribute_quoting_normally_uses_double_quotes(self):
        self.assertEqual(self.sub.substitute_xml("Welcome", True),
                          '"Welcome"')
        self.assertEqual(self.sub.substitute_xml("Bob's Bar", True),
                          '"Bob\'s Bar"')

    def test_xml_attribute_quoting_uses_single_quotes_when_value_contains_double_quotes(self):
        s = 'Welcome to "my bar"'
        self.assertEqual(self.sub.substitute_xml(s, True),
                          "'Welcome to \"my bar\"'")

    def test_xml_attribute_quoting_escapes_single_quotes_when_value_contains_both_single_and_double_quotes(self):
        s = 'Welcome to "Bob\'s Bar"'
        self.assertEqual(
            self.sub.substitute_xml(s, True),
            '"Welcome to &quot;Bob\'s Bar&quot;"')

    def test_xml_quotes_arent_escaped_when_value_is_not_being_quoted(self):
        quoted = 'Welcome to "Bob\'s Bar"'
        self.assertEqual(self.sub.substitute_xml(quoted), quoted)

    def test_xml_quoting_handles_angle_brackets(self):
        self.assertEqual(
            self.sub.substitute_xml("foo<bar>"),
            "foo&lt;bar&gt;")

    def test_xml_quoting_handles_ampersands(self):
        self.assertEqual(self.sub.substitute_xml("AT&T"), "AT&amp;T")

    def test_xml_quoting_including_ampersands_when_they_are_part_of_an_entity(self):
        self.assertEqual(
            self.sub.substitute_xml("&Aacute;T&T"),
            "&amp;Aacute;T&amp;T")

    def test_xml_quoting_ignoring_ampersands_when_they_are_part_of_an_entity(self):
        self.assertEqual(
            self.sub.substitute_xml_containing_entities("&Aacute;T&T"),
            "&Aacute;T&amp;T")

    def test_quotes_not_html_substituted(self):
        """There's no need to do this except inside attribute values."""
        text = 'Bob\'s "bar"'
        self.assertEqual(self.sub.substitute_html(text), text)


class TestEncodingConversion(SoupTest):
    # Test Beautiful Soup's ability to decode and encode from various
    # encodings.

    def setUp(self):
        super(TestEncodingConversion, self).setUp()
        self.unicode_data = u'<html><head><meta charset="utf-8"/></head><body><foo>Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!</foo></body></html>'
        self.utf8_data = self.unicode_data.encode("utf-8")
        # Just so you know what it looks like.
        self.assertEqual(
            self.utf8_data,
            b'<html><head><meta charset="utf-8"/></head><body><foo>Sacr\xc3\xa9 bleu!</foo></body></html>')

    def test_ascii_in_unicode_out(self):
        # ASCII input is converted to Unicode. The original_encoding
        # attribute is set to 'utf-8', a superset of ASCII.
        chardet = bs4.dammit.chardet_dammit
        logging.disable(logging.WARNING)
        try:
            def noop(str):
                return None
            # Disable chardet, which will realize that the ASCII is ASCII.
            bs4.dammit.chardet_dammit = noop
            ascii = b"<foo>a</foo>"
            soup_from_ascii = self.soup(ascii)
            unicode_output = soup_from_ascii.decode()
            self.assertTrue(isinstance(unicode_output, unicode))
            self.assertEqual(unicode_output, self.document_for(ascii.decode()))
            self.assertEqual(soup_from_ascii.original_encoding.lower(), "utf-8")
        finally:
            logging.disable(logging.NOTSET)
            bs4.dammit.chardet_dammit = chardet

    def test_unicode_in_unicode_out(self):
        # Unicode input is left alone. The original_encoding attribute
        # is not set.
        soup_from_unicode = self.soup(self.unicode_data)
        self.assertEqual(soup_from_unicode.decode(), self.unicode_data)
        self.assertEqual(soup_from_unicode.foo.string, u'Sacr\xe9 bleu!')
        self.assertEqual(soup_from_unicode.original_encoding, None)

    def test_utf8_in_unicode_out(self):
        # UTF-8 input is converted to Unicode. The original_encoding
        # attribute is set.
        soup_from_utf8 = self.soup(self.utf8_data)
        self.assertEqual(soup_from_utf8.decode(), self.unicode_data)
        self.assertEqual(soup_from_utf8.foo.string, u'Sacr\xe9 bleu!')

    def test_utf8_out(self):
        # The internal data structures can be encoded as UTF-8.
        soup_from_unicode = self.soup(self.unicode_data)
        self.assertEqual(soup_from_unicode.encode('utf-8'), self.utf8_data)

    @skipIf(
        PYTHON_2_PRE_2_7 or PYTHON_3_PRE_3_2,
        "Bad HTMLParser detected; skipping test of non-ASCII characters in attribute name.")
    def test_attribute_name_containing_unicode_characters(self):
        markup = u'<div><a \N{SNOWMAN}="snowman"></a></div>'
        self.assertEqual(self.soup(markup).div.encode("utf8"), markup.encode("utf8"))

class TestUnicodeDammit(unittest.TestCase):
    """Standalone tests of UnicodeDammit."""

    def test_unicode_input(self):
        markup = u"I'm already Unicode! \N{SNOWMAN}"
        dammit = UnicodeDammit(markup)
        self.assertEqual(dammit.unicode_markup, markup)

    def test_smart_quotes_to_unicode(self):
        markup = b"<foo>\x91\x92\x93\x94</foo>"
        dammit = UnicodeDammit(markup)
        self.assertEqual(
            dammit.unicode_markup, u"<foo>\u2018\u2019\u201c\u201d</foo>")

    def test_smart_quotes_to_xml_entities(self):
        markup = b"<foo>\x91\x92\x93\x94</foo>"
        dammit = UnicodeDammit(markup, smart_quotes_to="xml")
        self.assertEqual(
            dammit.unicode_markup, "<foo>&#x2018;&#x2019;&#x201C;&#x201D;</foo>")

    def test_smart_quotes_to_html_entities(self):
        markup = b"<foo>\x91\x92\x93\x94</foo>"
        dammit = UnicodeDammit(markup, smart_quotes_to="html")
        self.assertEqual(
            dammit.unicode_markup, "<foo>&lsquo;&rsquo;&ldquo;&rdquo;</foo>")

    def test_smart_quotes_to_ascii(self):
        markup = b"<foo>\x91\x92\x93\x94</foo>"
        dammit = UnicodeDammit(markup, smart_quotes_to="ascii")
        self.assertEqual(
            dammit.unicode_markup, """<foo>''""</foo>""")

    def test_detect_utf8(self):
        utf8 = b"Sacr\xc3\xa9 bleu! \xe2\x98\x83"
        dammit = UnicodeDammit(utf8)
        self.assertEqual(dammit.original_encoding.lower(), 'utf-8')
        self.assertEqual(dammit.unicode_markup, u'Sacr\xe9 bleu! \N{SNOWMAN}')


    def test_convert_hebrew(self):
        hebrew = b"\xed\xe5\xec\xf9"
        dammit = UnicodeDammit(hebrew, ["iso-8859-8"])
        self.assertEqual(dammit.original_encoding.lower(), 'iso-8859-8')
        self.assertEqual(dammit.unicode_markup, u'\u05dd\u05d5\u05dc\u05e9')

    def test_dont_see_smart_quotes_where_there_are_none(self):
        utf_8 = b"\343\202\261\343\203\274\343\202\277\343\202\244 Watch"
        dammit = UnicodeDammit(utf_8)
        self.assertEqual(dammit.original_encoding.lower(), 'utf-8')
        self.assertEqual(dammit.unicode_markup.encode("utf-8"), utf_8)

    def test_ignore_inappropriate_codecs(self):
        utf8_data = u"Räksmörgås".encode("utf-8")
        dammit = UnicodeDammit(utf8_data, ["iso-8859-8"])
        self.assertEqual(dammit.original_encoding.lower(), 'utf-8')

    def test_ignore_invalid_codecs(self):
        utf8_data = u"Räksmörgås".encode("utf-8")
        for bad_encoding in ['.utf8', '...', 'utF---16.!']:
            dammit = UnicodeDammit(utf8_data, [bad_encoding])
            self.assertEqual(dammit.original_encoding.lower(), 'utf-8')

    def test_exclude_encodings(self):
        # This is UTF-8.
        utf8_data = u"Räksmörgås".encode("utf-8")

        # But if we exclude UTF-8 from consideration, the guess is
        # Windows-1252.
        dammit = UnicodeDammit(utf8_data, exclude_encodings=["utf-8"])
        self.assertEqual(dammit.original_encoding.lower(), 'windows-1252')

        # And if we exclude that, there is no valid guess at all.
        dammit = UnicodeDammit(
            utf8_data, exclude_encodings=["utf-8", "windows-1252"])
        self.assertEqual(dammit.original_encoding, None)

    def test_encoding_detector_replaces_junk_in_encoding_name_with_replacement_character(self):
        detected = EncodingDetector(
            b'<?xml version="1.0" encoding="UTF-\xdb" ?>')
        encodings = list(detected.encodings)
        assert u'utf-\N{REPLACEMENT CHARACTER}' in encodings

    def test_detect_html5_style_meta_tag(self):

        for data in (
            b'<html><meta charset="euc-jp" /></html>',
            b"<html><meta charset='euc-jp' /></html>",
            b"<html><meta charset=euc-jp /></html>",
            b"<html><meta charset=euc-jp/></html>"):
            dammit = UnicodeDammit(data, is_html=True)
            self.assertEqual(
                "euc-jp", dammit.original_encoding)

    def test_last_ditch_entity_replacement(self):
        # This is a UTF-8 document that contains bytestrings
        # completely incompatible with UTF-8 (ie. encoded with some other
        # encoding).
        #
        # Since there is no consistent encoding for the document,
        # Unicode, Dammit will eventually encode the document as UTF-8
        # and encode the incompatible characters as REPLACEMENT
        # CHARACTER.
        #
        # If chardet is installed, it will detect that the document
        # can be converted into ISO-8859-1 without errors. This happens
        # to be the wrong encoding, but it is a consistent encoding, so the
        # code we're testing here won't run.
        #
        # So we temporarily disable chardet if it's present.
        doc = b"""\357\273\277<?xml version="1.0" encoding="UTF-8"?>
<html><b>\330\250\330\252\330\261</b>
<i>\310\322\321\220\312\321\355\344</i></html>"""
        chardet = bs4.dammit.chardet_dammit
        logging.disable(logging.WARNING)
        try:
            def noop(str):
                return None
            bs4.dammit.chardet_dammit = noop
            dammit = UnicodeDammit(doc)
            self.assertEqual(True, dammit.contains_replacement_characters)
            self.assertTrue(u"\ufffd" in dammit.unicode_markup)

            soup = BeautifulSoup(doc, "html.parser")
            self.assertTrue(soup.contains_replacement_characters)
        finally:
            logging.disable(logging.NOTSET)
            bs4.dammit.chardet_dammit = chardet

    def test_byte_order_mark_removed(self):
        # A document written in UTF-16LE will have its byte order marker stripped.
        data = b'\xff\xfe<\x00a\x00>\x00\xe1\x00\xe9\x00<\x00/\x00a\x00>\x00'
        dammit = UnicodeDammit(data)
        self.assertEqual(u"<a>áé</a>", dammit.unicode_markup)
        self.assertEqual("utf-16le", dammit.original_encoding)

    def test_detwingle(self):
        # Here's a UTF8 document.
        utf8 = (u"\N{SNOWMAN}" * 3).encode("utf8")

        # Here's a Windows-1252 document.
        windows_1252 = (
            u"\N{LEFT DOUBLE QUOTATION MARK}Hi, I like Windows!"
            u"\N{RIGHT DOUBLE QUOTATION MARK}").encode("windows_1252")

        # Through some unholy alchemy, they've been stuck together.
        doc = utf8 + windows_1252 + utf8

        # The document can't be turned into UTF-8:
        self.assertRaises(UnicodeDecodeError, doc.decode, "utf8")

        # Unicode, Dammit thinks the whole document is Windows-1252,
        # and decodes it into "â˜ƒâ˜ƒâ˜ƒ“Hi, I like Windows!”â˜ƒâ˜ƒâ˜ƒ"

        # But if we run it through fix_embedded_windows_1252, it's fixed:

        fixed = UnicodeDammit.detwingle(doc)
        self.assertEqual(
            u"☃☃☃“Hi, I like Windows!”☃☃☃", fixed.decode("utf8"))

    def test_detwingle_ignores_multibyte_characters(self):
        # Each of these characters has a UTF-8 representation ending
        # in \x93. \x93 is a smart quote if interpreted as
        # Windows-1252. But our code knows to skip over multibyte
        # UTF-8 characters, so they'll survive the process unscathed.
        for tricky_unicode_char in (
            u"\N{LATIN SMALL LIGATURE OE}", # 2-byte char '\xc5\x93'
            u"\N{LATIN SUBSCRIPT SMALL LETTER X}", # 3-byte char '\xe2\x82\x93'
            u"\xf0\x90\x90\x93", # This is a CJK character, not sure which one.
            ):
            input = tricky_unicode_char.encode("utf8")
            self.assertTrue(input.endswith(b'\x93'))
            output = UnicodeDammit.detwingle(input)
            self.assertEqual(output, input)

class TestNamedspacedAttribute(SoupTest):

    def test_name_may_be_none(self):
        a = NamespacedAttribute("xmlns", None)
        self.assertEqual(a, "xmlns")

    def test_attribute_is_equivalent_to_colon_separated_string(self):
        a = NamespacedAttribute("a", "b")
        self.assertEqual("a:b", a)

    def test_attributes_are_equivalent_if_prefix_and_name_identical(self):
        a = NamespacedAttribute("a", "b", "c")
        b = NamespacedAttribute("a", "b", "c")
        self.assertEqual(a, b)

        # The actual namespace is not considered.
        c = NamespacedAttribute("a", "b", None)
        self.assertEqual(a, c)

        # But name and prefix are important.
        d = NamespacedAttribute("a", "z", "c")
        self.assertNotEqual(a, d)

        e = NamespacedAttribute("z", "b", "c")
        self.assertNotEqual(a, e)


class TestAttributeValueWithCharsetSubstitution(unittest.TestCase):

    def test_content_meta_attribute_value(self):
        value = CharsetMetaAttributeValue("euc-jp")
        self.assertEqual("euc-jp", value)
        self.assertEqual("euc-jp", value.original_value)
        self.assertEqual("utf8", value.encode("utf8"))


    def test_content_meta_attribute_value(self):
        value = ContentMetaAttributeValue("text/html; charset=euc-jp")
        self.assertEqual("text/html; charset=euc-jp", value)
        self.assertEqual("text/html; charset=euc-jp", value.original_value)
        self.assertEqual("text/html; charset=utf8", value.encode("utf8"))
