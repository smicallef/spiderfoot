"""Unicode utility functions

>>> from .import unicode_util
>>> from .util import u
>>> u1 = '1'  # DIGIT ONE
>>> u2 = u('a')  # LATIN SMALL LETTER A
>>> u3 = u('\uFF12')  # FULLWIDTH DIGIT TWO
>>> u4 = u('\u0100')  # LATIN CAPITAL LETTER A WITH MACRON
>>> unicode_util.Category.get(u1) == u('Nd')
True
>>> unicode_util.Category.get(u2) == u('Ll')
True
>>> unicode_util.Category.get(u3) == u('Nd')
True
>>> unicode_util.Category.get(u4) == u('Lu')
True
>>> unicode_util.Category.get(u2) == unicode_util.Category.LOWERCASE_LETTER
True
>>> try:
...     beyond_bmp = u('\U00010100')  # AEGEAN WORD SEPARATOR LINE
... except Exception:
...     beyond_bmp = u('')
>>> if len(beyond_bmp) == 1:  # We have a UCS4 build of Python
...     cat_po = unicode_util.Category.get(beyond_bmp)
... else:  # UCS2 build of Python; no non-BMP chars available
...     cat_po = unicode_util.Category.OTHER_PUNCTUATION
>>> cat_po == u('Po')
True
>>> unicode_util.is_letter(u1)
False
>>> unicode_util.is_letter(u2)
True
>>> unicode_util.is_letter(u3)
False
>>> unicode_util.is_letter(u4)
True
>>> b1 = unicode_util.Block.get(u1)
>>> str(b1)
'Block[0000, 007f]'
>>> b1 == unicode_util.Block.BASIC_LATIN
True
>>> b2 = unicode_util.Block.get(u2)
>>> b2 == unicode_util.Block.BASIC_LATIN
True
>>> b3 = unicode_util.Block.get(u3)
>>> b3 != unicode_util.Block.BASIC_LATIN
True
>>> b3 == unicode_util.Block.HALFWIDTH_AND_FULLWIDTH_FORMS
True
>>> b4 = unicode_util.Block.get(u4)
>>> b4 == unicode_util.Block.LATIN_EXTENDED_A
True
>>> unicode_util.Block.get(u('\u0860')) == unicode_util.Block.UNKNOWN
True
>>> try:
...     unknown_block = u('\U00013430')
... except Exception:
...     unknown_block = u('')
>>> if len(unknown_block) == 1:  # We have a UCS4 build of Python
...     unicode_util.Block.get(u('\U00013430')) == unicode_util.Block.UNKNOWN
... else:  # UCS2 build of Python; no unknown characters available
...     True
True
>>> unicode_util.digit(u1)
1
>>> unicode_util.digit(u2, -1)
-1
>>> unicode_util.digit(u3, -1)
2
>>> str(hash(b3))  # doctest: +ELLIPSIS
'...'
"""
import bisect
import unicodedata  # Python 2.5 onward

from .util import UnicodeMixin, unicod, u


class Category(object):
    """General category of a Unicode character.

    See http://www.unicode.org/reports/tr18/#Categories"""
    LETTER = u("L")
    UPPERCASE_LETTER = u("Lu")
    LOWERCASE_LETTER = u("Ll")
    TITLECASE_LETTER = u("Lt")
    MODIFIER_LETTER = u("Lm")
    OTHER_LETTER = u("Lo")
    MARK = u("M")
    NON_SPACING_MARK = u("Mn")
    SPACING_COMBINING_MARK = u("Mc")
    ENCLOSING_MARK = u("Me")
    NUMBER = u("N")
    DECIMAL_DIGIT_NUMBER = u("Nd")
    LETTER_NUMBER = u("Nl")
    OTHER_NUMBER = u("No")
    SYMBOL = u("S")
    MATH_SYMBOL = u("Sm")
    CURRENCY_SYMBOL = u("Sc")
    MODIFIER_SYMBOL = u("Sk")
    OTHER_SYMBOL = u("So")
    PUNCTUATION = u("P")
    CONNECTOR_PUNCTUATION = u("Pc")
    DASH_PUNCTUATION = u("Pd")
    OPEN_PUNCTUATION = u("Ps")
    CLOSE_PUNCTUATION = u("Pe")
    INITIAL_PUNCTUATION = u("Pi")
    FINAL_PUNCTUATION = u("Pf")
    OTHER_PUNCTUATION = u("Po")
    SEPARATOR = u("Z")
    SPACE_SEPARATOR = u("Zs")
    LINE_SEPARATOR = u("Zl")
    PARAGRAPH_SEPARATOR = u("Zp")
    OTHER = u("C")
    CONTROL = u("Cc")
    FORMAT = u("Cf")
    SURROGATE = u("Cs")
    PRIVATE_USE = u("Co")
    NOT_ASSIGNED = u("Cn")

    @classmethod
    def get(cls, uni_char):
        """Return the general category code (as Unicode string) for the given Unicode character"""
        uni_char = unicod(uni_char)  # Force to Unicode
        return unicod(unicodedata.category(uni_char))


def is_letter(uni_char):
    """Determine whether the given Unicode character is a Unicode letter"""
    category = Category.get(uni_char)
    return (category == Category.UPPERCASE_LETTER or
            category == Category.LOWERCASE_LETTER or
            category == Category.TITLECASE_LETTER or
            category == Category.MODIFIER_LETTER or
            category == Category.OTHER_LETTER)


class _BlockRange(UnicodeMixin):
    """Describe the range of characters encompassed by a Unicode block"""
    def __init__(self, start, end, regdict=None):
        self.start = start
        self.end = end
        if regdict is not None:
            regdict[start] = self

    def __eq__(self, other):
        return (self.start == other.start and self.end == other.end)

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.start, self.end))

    def __unicode__(self):
        return unicod("Block[%04x, %04x]") % (self.start, self.end)


class Block(object):
    """Description of the possible Unicode blocks"""

    _RANGES = {}  # lower end of range => _BlockRange object
    _RANGE_KEYS = None  # sorted list of _RANGES.keys()

    # Taken from http://www.unicode.org/Public/UNIDATA/Blocks.txt
    BASIC_LATIN = _BlockRange(0x0000, 0x007F, _RANGES)
    LATIN_1_SUPPLEMENT = _BlockRange(0x0080, 0x00FF, _RANGES)
    LATIN_EXTENDED_A = _BlockRange(0x0100, 0x017F, _RANGES)
    LATIN_EXTENDED_B = _BlockRange(0x0180, 0x024F, _RANGES)
    IPA_EXTENSIONS = _BlockRange(0x0250, 0x02AF, _RANGES)
    SPACING_MODIFIER_LETTERS = _BlockRange(0x02B0, 0x02FF, _RANGES)
    COMBINING_DIACRITICAL_MARKS = _BlockRange(0x0300, 0x036F, _RANGES)
    GREEK_AND_COPTIC = _BlockRange(0x0370, 0x03FF, _RANGES)
    CYRILLIC = _BlockRange(0x0400, 0x04FF, _RANGES)
    CYRILLIC_SUPPLEMENT = _BlockRange(0x0500, 0x052F, _RANGES)
    ARMENIAN = _BlockRange(0x0530, 0x058F, _RANGES)
    HEBREW = _BlockRange(0x0590, 0x05FF, _RANGES)
    ARABIC = _BlockRange(0x0600, 0x06FF, _RANGES)
    SYRIAC = _BlockRange(0x0700, 0x074F, _RANGES)
    ARABIC_SUPPLEMENT = _BlockRange(0x0750, 0x077F, _RANGES)
    THAANA = _BlockRange(0x0780, 0x07BF, _RANGES)
    NKO = _BlockRange(0x07C0, 0x07FF, _RANGES)
    SAMARITAN = _BlockRange(0x0800, 0x083F, _RANGES)
    MANDAIC = _BlockRange(0x0840, 0x085F, _RANGES)
    DEVANAGARI = _BlockRange(0x0900, 0x097F, _RANGES)
    BENGALI = _BlockRange(0x0980, 0x09FF, _RANGES)
    GURMUKHI = _BlockRange(0x0A00, 0x0A7F, _RANGES)
    GUJARATI = _BlockRange(0x0A80, 0x0AFF, _RANGES)
    ORIYA = _BlockRange(0x0B00, 0x0B7F, _RANGES)
    TAMIL = _BlockRange(0x0B80, 0x0BFF, _RANGES)
    TELUGU = _BlockRange(0x0C00, 0x0C7F, _RANGES)
    KANNADA = _BlockRange(0x0C80, 0x0CFF, _RANGES)
    MALAYALAM = _BlockRange(0x0D00, 0x0D7F, _RANGES)
    SINHALA = _BlockRange(0x0D80, 0x0DFF, _RANGES)
    THAI = _BlockRange(0x0E00, 0x0E7F, _RANGES)
    LAO = _BlockRange(0x0E80, 0x0EFF, _RANGES)
    TIBETAN = _BlockRange(0x0F00, 0x0FFF, _RANGES)
    MYANMAR = _BlockRange(0x1000, 0x109F, _RANGES)
    GEORGIAN = _BlockRange(0x10A0, 0x10FF, _RANGES)
    HANGUL_JAMO = _BlockRange(0x1100, 0x11FF, _RANGES)
    ETHIOPIC = _BlockRange(0x1200, 0x137F, _RANGES)
    ETHIOPIC_SUPPLEMENT = _BlockRange(0x1380, 0x139F, _RANGES)
    CHEROKEE = _BlockRange(0x13A0, 0x13FF, _RANGES)
    UNIFIED_CANADIAN_ABORIGINAL_SYLLABICS = _BlockRange(0x1400, 0x167F, _RANGES)
    OGHAM = _BlockRange(0x1680, 0x169F, _RANGES)
    RUNIC = _BlockRange(0x16A0, 0x16FF, _RANGES)
    TAGALOG = _BlockRange(0x1700, 0x171F, _RANGES)
    HANUNOO = _BlockRange(0x1720, 0x173F, _RANGES)
    BUHID = _BlockRange(0x1740, 0x175F, _RANGES)
    TAGBANWA = _BlockRange(0x1760, 0x177F, _RANGES)
    KHMER = _BlockRange(0x1780, 0x17FF, _RANGES)
    MONGOLIAN = _BlockRange(0x1800, 0x18AF, _RANGES)
    UNIFIED_CANADIAN_ABORIGINAL_SYLLABICS_EXTENDED = _BlockRange(0x18B0, 0x18FF, _RANGES)
    LIMBU = _BlockRange(0x1900, 0x194F, _RANGES)
    TAI_LE = _BlockRange(0x1950, 0x197F, _RANGES)
    NEW_TAI_LUE = _BlockRange(0x1980, 0x19DF, _RANGES)
    KHMER_SYMBOLS = _BlockRange(0x19E0, 0x19FF, _RANGES)
    BUGINESE = _BlockRange(0x1A00, 0x1A1F, _RANGES)
    TAI_THAM = _BlockRange(0x1A20, 0x1AAF, _RANGES)
    BALINESE = _BlockRange(0x1B00, 0x1B7F, _RANGES)
    SUNDANESE = _BlockRange(0x1B80, 0x1BBF, _RANGES)
    BATAK = _BlockRange(0x1BC0, 0x1BFF, _RANGES)
    LEPCHA = _BlockRange(0x1C00, 0x1C4F, _RANGES)
    OL_CHIKI = _BlockRange(0x1C50, 0x1C7F, _RANGES)
    VEDIC_EXTENSIONS = _BlockRange(0x1CD0, 0x1CFF, _RANGES)
    PHONETIC_EXTENSIONS = _BlockRange(0x1D00, 0x1D7F, _RANGES)
    PHONETIC_EXTENSIONS_SUPPLEMENT = _BlockRange(0x1D80, 0x1DBF, _RANGES)
    COMBINING_DIACRITICAL_MARKS_SUPPLEMENT = _BlockRange(0x1DC0, 0x1DFF, _RANGES)
    LATIN_EXTENDED_ADDITIONAL = _BlockRange(0x1E00, 0x1EFF, _RANGES)
    GREEK_EXTENDED = _BlockRange(0x1F00, 0x1FFF, _RANGES)
    GENERAL_PUNCTUATION = _BlockRange(0x2000, 0x206F, _RANGES)
    SUPERSCRIPTS_AND_SUBSCRIPTS = _BlockRange(0x2070, 0x209F, _RANGES)
    CURRENCY_SYMBOLS = _BlockRange(0x20A0, 0x20CF, _RANGES)
    COMBINING_DIACRITICAL_MARKS_FOR_SYMBOLS = _BlockRange(0x20D0, 0x20FF, _RANGES)
    LETTERLIKE_SYMBOLS = _BlockRange(0x2100, 0x214F, _RANGES)
    NUMBER_FORMS = _BlockRange(0x2150, 0x218F, _RANGES)
    ARROWS = _BlockRange(0x2190, 0x21FF, _RANGES)
    MATHEMATICAL_OPERATORS = _BlockRange(0x2200, 0x22FF, _RANGES)
    MISCELLANEOUS_TECHNICAL = _BlockRange(0x2300, 0x23FF, _RANGES)
    CONTROL_PICTURES = _BlockRange(0x2400, 0x243F, _RANGES)
    OPTICAL_CHARACTER_RECOGNITION = _BlockRange(0x2440, 0x245F, _RANGES)
    ENCLOSED_ALPHANUMERICS = _BlockRange(0x2460, 0x24FF, _RANGES)
    BOX_DRAWING = _BlockRange(0x2500, 0x257F, _RANGES)
    BLOCK_ELEMENTS = _BlockRange(0x2580, 0x259F, _RANGES)
    GEOMETRIC_SHAPES = _BlockRange(0x25A0, 0x25FF, _RANGES)
    MISCELLANEOUS_SYMBOLS = _BlockRange(0x2600, 0x26FF, _RANGES)
    DINGBATS = _BlockRange(0x2700, 0x27BF, _RANGES)
    MISCELLANEOUS_MATHEMATICAL_SYMBOLS_A = _BlockRange(0x27C0, 0x27EF, _RANGES)
    SUPPLEMENTAL_ARROWS_A = _BlockRange(0x27F0, 0x27FF, _RANGES)
    BRAILLE_PATTERNS = _BlockRange(0x2800, 0x28FF, _RANGES)
    SUPPLEMENTAL_ARROWS_B = _BlockRange(0x2900, 0x297F, _RANGES)
    MISCELLANEOUS_MATHEMATICAL_SYMBOLS_B = _BlockRange(0x2980, 0x29FF, _RANGES)
    SUPPLEMENTAL_MATHEMATICAL_OPERATORS = _BlockRange(0x2A00, 0x2AFF, _RANGES)
    MISCELLANEOUS_SYMBOLS_AND_ARROWS = _BlockRange(0x2B00, 0x2BFF, _RANGES)
    GLAGOLITIC = _BlockRange(0x2C00, 0x2C5F, _RANGES)
    LATIN_EXTENDED_C = _BlockRange(0x2C60, 0x2C7F, _RANGES)
    COPTIC = _BlockRange(0x2C80, 0x2CFF, _RANGES)
    GEORGIAN_SUPPLEMENT = _BlockRange(0x2D00, 0x2D2F, _RANGES)
    TIFINAGH = _BlockRange(0x2D30, 0x2D7F, _RANGES)
    ETHIOPIC_EXTENDED = _BlockRange(0x2D80, 0x2DDF, _RANGES)
    CYRILLIC_EXTENDED_A = _BlockRange(0x2DE0, 0x2DFF, _RANGES)
    SUPPLEMENTAL_PUNCTUATION = _BlockRange(0x2E00, 0x2E7F, _RANGES)
    CJK_RADICALS_SUPPLEMENT = _BlockRange(0x2E80, 0x2EFF, _RANGES)
    KANGXI_RADICALS = _BlockRange(0x2F00, 0x2FDF, _RANGES)
    IDEOGRAPHIC_DESCRIPTION_CHARACTERS = _BlockRange(0x2FF0, 0x2FFF, _RANGES)
    CJK_SYMBOLS_AND_PUNCTUATION = _BlockRange(0x3000, 0x303F, _RANGES)
    HIRAGANA = _BlockRange(0x3040, 0x309F, _RANGES)
    KATAKANA = _BlockRange(0x30A0, 0x30FF, _RANGES)
    BOPOMOFO = _BlockRange(0x3100, 0x312F, _RANGES)
    HANGUL_COMPATIBILITY_JAMO = _BlockRange(0x3130, 0x318F, _RANGES)
    KANBUN = _BlockRange(0x3190, 0x319F, _RANGES)
    BOPOMOFO_EXTENDED = _BlockRange(0x31A0, 0x31BF, _RANGES)
    CJK_STROKES = _BlockRange(0x31C0, 0x31EF, _RANGES)
    KATAKANA_PHONETIC_EXTENSIONS = _BlockRange(0x31F0, 0x31FF, _RANGES)
    ENCLOSED_CJK_LETTERS_AND_MONTHS = _BlockRange(0x3200, 0x32FF, _RANGES)
    CJK_COMPATIBILITY = _BlockRange(0x3300, 0x33FF, _RANGES)
    CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A = _BlockRange(0x3400, 0x4DBF, _RANGES)
    YIJING_HEXAGRAM_SYMBOLS = _BlockRange(0x4DC0, 0x4DFF, _RANGES)
    CJK_UNIFIED_IDEOGRAPHS = _BlockRange(0x4E00, 0x9FFF, _RANGES)
    YI_SYLLABLES = _BlockRange(0xA000, 0xA48F, _RANGES)
    YI_RADICALS = _BlockRange(0xA490, 0xA4CF, _RANGES)
    LISU = _BlockRange(0xA4D0, 0xA4FF, _RANGES)
    VAI = _BlockRange(0xA500, 0xA63F, _RANGES)
    CYRILLIC_EXTENDED_B = _BlockRange(0xA640, 0xA69F, _RANGES)
    BAMUM = _BlockRange(0xA6A0, 0xA6FF, _RANGES)
    MODIFIER_TONE_LETTERS = _BlockRange(0xA700, 0xA71F, _RANGES)
    LATIN_EXTENDED_D = _BlockRange(0xA720, 0xA7FF, _RANGES)
    SYLOTI_NAGRI = _BlockRange(0xA800, 0xA82F, _RANGES)
    COMMON_INDIC_NUMBER_FORMS = _BlockRange(0xA830, 0xA83F, _RANGES)
    PHAGS_PA = _BlockRange(0xA840, 0xA87F, _RANGES)
    SAURASHTRA = _BlockRange(0xA880, 0xA8DF, _RANGES)
    DEVANAGARI_EXTENDED = _BlockRange(0xA8E0, 0xA8FF, _RANGES)
    KAYAH_LI = _BlockRange(0xA900, 0xA92F, _RANGES)
    REJANG = _BlockRange(0xA930, 0xA95F, _RANGES)
    HANGUL_JAMO_EXTENDED_A = _BlockRange(0xA960, 0xA97F, _RANGES)
    JAVANESE = _BlockRange(0xA980, 0xA9DF, _RANGES)
    CHAM = _BlockRange(0xAA00, 0xAA5F, _RANGES)
    MYANMAR_EXTENDED_A = _BlockRange(0xAA60, 0xAA7F, _RANGES)
    TAI_VIET = _BlockRange(0xAA80, 0xAADF, _RANGES)
    ETHIOPIC_EXTENDED_A = _BlockRange(0xAB00, 0xAB2F, _RANGES)
    MEETEI_MAYEK = _BlockRange(0xABC0, 0xABFF, _RANGES)
    HANGUL_SYLLABLES = _BlockRange(0xAC00, 0xD7AF, _RANGES)
    HANGUL_JAMO_EXTENDED_B = _BlockRange(0xD7B0, 0xD7FF, _RANGES)
    HIGH_SURROGATES = _BlockRange(0xD800, 0xDB7F, _RANGES)
    HIGH_PRIVATE_USE_SURROGATES = _BlockRange(0xDB80, 0xDBFF, _RANGES)
    LOW_SURROGATES = _BlockRange(0xDC00, 0xDFFF, _RANGES)
    PRIVATE_USE_AREA = _BlockRange(0xE000, 0xF8FF, _RANGES)
    CJK_COMPATIBILITY_IDEOGRAPHS = _BlockRange(0xF900, 0xFAFF, _RANGES)
    ALPHABETIC_PRESENTATION_FORMS = _BlockRange(0xFB00, 0xFB4F, _RANGES)
    ARABIC_PRESENTATION_FORMS_A = _BlockRange(0xFB50, 0xFDFF, _RANGES)
    VARIATION_SELECTORS = _BlockRange(0xFE00, 0xFE0F, _RANGES)
    VERTICAL_FORMS = _BlockRange(0xFE10, 0xFE1F, _RANGES)
    COMBINING_HALF_MARKS = _BlockRange(0xFE20, 0xFE2F, _RANGES)
    CJK_COMPATIBILITY_FORMS = _BlockRange(0xFE30, 0xFE4F, _RANGES)
    SMALL_FORM_VARIANTS = _BlockRange(0xFE50, 0xFE6F, _RANGES)
    ARABIC_PRESENTATION_FORMS_B = _BlockRange(0xFE70, 0xFEFF, _RANGES)
    HALFWIDTH_AND_FULLWIDTH_FORMS = _BlockRange(0xFF00, 0xFFEF, _RANGES)
    SPECIALS = _BlockRange(0xFFF0, 0xFFFF, _RANGES)
    LINEAR_B_SYLLABARY = _BlockRange(0x10000, 0x1007F, _RANGES)
    LINEAR_B_IDEOGRAMS = _BlockRange(0x10080, 0x100FF, _RANGES)
    AEGEAN_NUMBERS = _BlockRange(0x10100, 0x1013F, _RANGES)
    ANCIENT_GREEK_NUMBERS = _BlockRange(0x10140, 0x1018F, _RANGES)
    ANCIENT_SYMBOLS = _BlockRange(0x10190, 0x101CF, _RANGES)
    PHAISTOS_DISC = _BlockRange(0x101D0, 0x101FF, _RANGES)
    LYCIAN = _BlockRange(0x10280, 0x1029F, _RANGES)
    CARIAN = _BlockRange(0x102A0, 0x102DF, _RANGES)
    OLD_ITALIC = _BlockRange(0x10300, 0x1032F, _RANGES)
    GOTHIC = _BlockRange(0x10330, 0x1034F, _RANGES)
    UGARITIC = _BlockRange(0x10380, 0x1039F, _RANGES)
    OLD_PERSIAN = _BlockRange(0x103A0, 0x103DF, _RANGES)
    DESERET = _BlockRange(0x10400, 0x1044F, _RANGES)
    SHAVIAN = _BlockRange(0x10450, 0x1047F, _RANGES)
    OSMANYA = _BlockRange(0x10480, 0x104AF, _RANGES)
    CYPRIOT_SYLLABARY = _BlockRange(0x10800, 0x1083F, _RANGES)
    IMPERIAL_ARAMAIC = _BlockRange(0x10840, 0x1085F, _RANGES)
    PHOENICIAN = _BlockRange(0x10900, 0x1091F, _RANGES)
    LYDIAN = _BlockRange(0x10920, 0x1093F, _RANGES)
    KHAROSHTHI = _BlockRange(0x10A00, 0x10A5F, _RANGES)
    OLD_SOUTH_ARABIAN = _BlockRange(0x10A60, 0x10A7F, _RANGES)
    AVESTAN = _BlockRange(0x10B00, 0x10B3F, _RANGES)
    INSCRIPTIONAL_PARTHIAN = _BlockRange(0x10B40, 0x10B5F, _RANGES)
    INSCRIPTIONAL_PAHLAVI = _BlockRange(0x10B60, 0x10B7F, _RANGES)
    OLD_TURKIC = _BlockRange(0x10C00, 0x10C4F, _RANGES)
    RUMI_NUMERAL_SYMBOLS = _BlockRange(0x10E60, 0x10E7F, _RANGES)
    BRAHMI = _BlockRange(0x11000, 0x1107F, _RANGES)
    KAITHI = _BlockRange(0x11080, 0x110CF, _RANGES)
    CUNEIFORM = _BlockRange(0x12000, 0x123FF, _RANGES)
    CUNEIFORM_NUMBERS_AND_PUNCTUATION = _BlockRange(0x12400, 0x1247F, _RANGES)
    EGYPTIAN_HIEROGLYPHS = _BlockRange(0x13000, 0x1342F, _RANGES)
    BAMUM_SUPPLEMENT = _BlockRange(0x16800, 0x16A3F, _RANGES)
    KANA_SUPPLEMENT = _BlockRange(0x1B000, 0x1B0FF, _RANGES)
    BYZANTINE_MUSICAL_SYMBOLS = _BlockRange(0x1D000, 0x1D0FF, _RANGES)
    MUSICAL_SYMBOLS = _BlockRange(0x1D100, 0x1D1FF, _RANGES)
    ANCIENT_GREEK_MUSICAL_NOTATION = _BlockRange(0x1D200, 0x1D24F, _RANGES)
    TAI_XUAN_JING_SYMBOLS = _BlockRange(0x1D300, 0x1D35F, _RANGES)
    COUNTING_ROD_NUMERALS = _BlockRange(0x1D360, 0x1D37F, _RANGES)
    MATHEMATICAL_ALPHANUMERIC_SYMBOLS = _BlockRange(0x1D400, 0x1D7FF, _RANGES)
    MAHJONG_TILES = _BlockRange(0x1F000, 0x1F02F, _RANGES)
    DOMINO_TILES = _BlockRange(0x1F030, 0x1F09F, _RANGES)
    PLAYING_CARDS = _BlockRange(0x1F0A0, 0x1F0FF, _RANGES)
    ENCLOSED_ALPHANUMERIC_SUPPLEMENT = _BlockRange(0x1F100, 0x1F1FF, _RANGES)
    ENCLOSED_IDEOGRAPHIC_SUPPLEMENT = _BlockRange(0x1F200, 0x1F2FF, _RANGES)
    MISCELLANEOUS_SYMBOLS_AND_PICTOGRAPHS = _BlockRange(0x1F300, 0x1F5FF, _RANGES)
    EMOTICONS = _BlockRange(0x1F600, 0x1F64F, _RANGES)
    TRANSPORT_AND_MAP_SYMBOLS = _BlockRange(0x1F680, 0x1F6FF, _RANGES)
    ALCHEMICAL_SYMBOLS = _BlockRange(0x1F700, 0x1F77F, _RANGES)
    CJK_UNIFIED_IDEOGRAPHS_EXTENSION_B = _BlockRange(0x20000, 0x2A6DF, _RANGES)
    CJK_UNIFIED_IDEOGRAPHS_EXTENSION_C = _BlockRange(0x2A700, 0x2B73F, _RANGES)
    CJK_UNIFIED_IDEOGRAPHS_EXTENSION_D = _BlockRange(0x2B740, 0x2B81F, _RANGES)
    CJK_COMPATIBILITY_IDEOGRAPHS_SUPPLEMENT = _BlockRange(0x2F800, 0x2FA1F, _RANGES)
    TAGS = _BlockRange(0xE0000, 0xE007F, _RANGES)
    VARIATION_SELECTORS_SUPPLEMENT = _BlockRange(0xE0100, 0xE01EF, _RANGES)
    SUPPLEMENTARY_PRIVATE_USE_AREA_A = _BlockRange(0xF0000, 0xFFFFF, _RANGES)
    SUPPLEMENTARY_PRIVATE_USE_AREA_B = _BlockRange(0x100000, 0x10FFFF, _RANGES)
    UNKNOWN = _BlockRange(-1, -1)

    @classmethod
    def get(cls, uni_char):
        """Return the Unicode block of the given Unicode character"""
        uni_char = unicod(uni_char)  # Force to Unicode
        code_point = ord(uni_char)
        if Block._RANGE_KEYS is None:
            Block._RANGE_KEYS = sorted(Block._RANGES.keys())
        idx = bisect.bisect_left(Block._RANGE_KEYS, code_point)
        if (idx > 0 and
            code_point >= Block._RANGES[Block._RANGE_KEYS[idx - 1]].start and
            code_point <= Block._RANGES[Block._RANGE_KEYS[idx - 1]].end):
            return Block._RANGES[Block._RANGE_KEYS[idx - 1]]
        elif (idx < len(Block._RANGES) and
              code_point >= Block._RANGES[Block._RANGE_KEYS[idx]].start and
              code_point <= Block._RANGES[Block._RANGE_KEYS[idx]].end):
            return Block._RANGES[Block._RANGE_KEYS[idx]]
        else:
            return Block.UNKNOWN


def digit(uni_char, default_value=None):
    """Returns the digit value assigned to the Unicode character uni_char as
    integer. If no such value is defined, default is returned, or, if not
    given, ValueError is raised."""
    uni_char = unicod(uni_char)  # Force to Unicode.
    if default_value is not None:
        return unicodedata.digit(uni_char, default_value)
    else:
        return unicodedata.digit(uni_char)

if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
