"""
Tag definitions
"""

from .exif import *
from . import makernote

DEFAULT_STOP_TAG = 'UNDEF'

# field type descriptions as (length, abbreviation, full name) tuples
FIELD_TYPES = (
    (0, 'X', 'Proprietary'),  # no such type
    (1, 'B', 'Byte'),
    (1, 'A', 'ASCII'),
    (2, 'S', 'Short'),
    (4, 'L', 'Long'),
    (8, 'R', 'Ratio'),
    (1, 'SB', 'Signed Byte'),
    (1, 'U', 'Undefined'),
    (2, 'SS', 'Signed Short'),
    (4, 'SL', 'Signed Long'),
    (8, 'SR', 'Signed Ratio'),
)

# To ignore when quick processing
IGNORE_TAGS = (
    0x9286,  # user comment
    0x927C,  # MakerNote Tags
    0x02BC,  # XPM
)
