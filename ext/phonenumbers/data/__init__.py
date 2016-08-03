"""Auto-generated file, do not edit by hand."""
# Copyright (C) 2010-2016 The Libphonenumber Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ..phonemetadata import PhoneMetadata

_AVAILABLE_REGION_CODES = ['AC','AD','AE','AF','AG','AI','AL','AM','AO','AR','AS','AT','AU','AW','AX','AZ','BA','BB','BD','BE','BF','BG','BH','BI','BJ','BL','BM','BN','BO','BQ','BR','BS','BT','BW','BY','BZ','CA','CC','CD','CF','CG','CH','CI','CK','CL','CM','CN','CO','CR','CU','CV','CW','CX','CY','CZ','DE','DJ','DK','DM','DO','DZ','EC','EE','EG','EH','ER','ES','ET','FI','FJ','FK','FM','FO','FR','GA','GB','GD','GE','GF','GG','GH','GI','GL','GM','GN','GP','GQ','GR','GT','GU','GW','GY','HK','HN','HR','HT','HU','ID','IE','IL','IM','IN','IO','IQ','IR','IS','IT','JE','JM','JO','JP','KE','KG','KH','KI','KM','KN','KP','KR','KW','KY','KZ','LA','LB','LC','LI','LK','LR','LS','LT','LU','LV','LY','MA','MC','MD','ME','MF','MG','MH','MK','ML','MM','MN','MO','MP','MQ','MR','MS','MT','MU','MV','MW','MX','MY','MZ','NA','NC','NE','NF','NG','NI','NL','NO','NP','NR','NU','NZ','OM','PA','PE','PF','PG','PH','PK','PL','PM','PR','PS','PT','PW','PY','QA','RE','RO','RS','RU','RW','SA','SB','SC','SD','SE','SG','SH','SI','SJ','SK','SL','SM','SN','SO','SR','SS','ST','SV','SX','SY','SZ','TA','TC','TD','TG','TH','TJ','TK','TL','TM','TN','TO','TR','TT','TV','TW','TZ','UA','UG','US','UY','UZ','VA','VC','VE','VG','VI','VN','VU','WF','WS','YE','YT','ZA','ZM','ZW']
_AVAILABLE_NONGEO_COUNTRY_CODES = [800, 808, 870, 878, 881, 882, 883, 888, 979]

def _load_region(code):
    __import__("region_%s" % code, globals(), locals(),
               fromlist=["PHONE_METADATA_%s" % code], level=1)

for region_code in _AVAILABLE_REGION_CODES:
    PhoneMetadata.register_region_loader(region_code, _load_region)


for country_code in _AVAILABLE_NONGEO_COUNTRY_CODES:
    PhoneMetadata.register_nongeo_region_loader(country_code, _load_region)

from .alt_format_255 import PHONE_ALT_FORMAT_255
from .alt_format_27 import PHONE_ALT_FORMAT_27
from .alt_format_30 import PHONE_ALT_FORMAT_30
from .alt_format_31 import PHONE_ALT_FORMAT_31
from .alt_format_34 import PHONE_ALT_FORMAT_34
from .alt_format_350 import PHONE_ALT_FORMAT_350
from .alt_format_351 import PHONE_ALT_FORMAT_351
from .alt_format_352 import PHONE_ALT_FORMAT_352
from .alt_format_358 import PHONE_ALT_FORMAT_358
from .alt_format_359 import PHONE_ALT_FORMAT_359
from .alt_format_36 import PHONE_ALT_FORMAT_36
from .alt_format_372 import PHONE_ALT_FORMAT_372
from .alt_format_373 import PHONE_ALT_FORMAT_373
from .alt_format_380 import PHONE_ALT_FORMAT_380
from .alt_format_381 import PHONE_ALT_FORMAT_381
from .alt_format_385 import PHONE_ALT_FORMAT_385
from .alt_format_43 import PHONE_ALT_FORMAT_43
from .alt_format_44 import PHONE_ALT_FORMAT_44
from .alt_format_49 import PHONE_ALT_FORMAT_49
from .alt_format_505 import PHONE_ALT_FORMAT_505
from .alt_format_506 import PHONE_ALT_FORMAT_506
from .alt_format_54 import PHONE_ALT_FORMAT_54
from .alt_format_55 import PHONE_ALT_FORMAT_55
from .alt_format_58 import PHONE_ALT_FORMAT_58
from .alt_format_595 import PHONE_ALT_FORMAT_595
from .alt_format_61 import PHONE_ALT_FORMAT_61
from .alt_format_62 import PHONE_ALT_FORMAT_62
from .alt_format_63 import PHONE_ALT_FORMAT_63
from .alt_format_66 import PHONE_ALT_FORMAT_66
from .alt_format_675 import PHONE_ALT_FORMAT_675
from .alt_format_676 import PHONE_ALT_FORMAT_676
from .alt_format_679 import PHONE_ALT_FORMAT_679
from .alt_format_7 import PHONE_ALT_FORMAT_7
from .alt_format_81 import PHONE_ALT_FORMAT_81
from .alt_format_84 import PHONE_ALT_FORMAT_84
from .alt_format_855 import PHONE_ALT_FORMAT_855
from .alt_format_90 import PHONE_ALT_FORMAT_90
from .alt_format_91 import PHONE_ALT_FORMAT_91
from .alt_format_94 import PHONE_ALT_FORMAT_94
from .alt_format_95 import PHONE_ALT_FORMAT_95
from .alt_format_971 import PHONE_ALT_FORMAT_971
from .alt_format_972 import PHONE_ALT_FORMAT_972
from .alt_format_995 import PHONE_ALT_FORMAT_995
_ALT_NUMBER_FORMATS = {255: PHONE_ALT_FORMAT_255, 27: PHONE_ALT_FORMAT_27, 30: PHONE_ALT_FORMAT_30, 31: PHONE_ALT_FORMAT_31, 34: PHONE_ALT_FORMAT_34, 350: PHONE_ALT_FORMAT_350, 351: PHONE_ALT_FORMAT_351, 352: PHONE_ALT_FORMAT_352, 358: PHONE_ALT_FORMAT_358, 359: PHONE_ALT_FORMAT_359, 36: PHONE_ALT_FORMAT_36, 372: PHONE_ALT_FORMAT_372, 373: PHONE_ALT_FORMAT_373, 380: PHONE_ALT_FORMAT_380, 381: PHONE_ALT_FORMAT_381, 385: PHONE_ALT_FORMAT_385, 43: PHONE_ALT_FORMAT_43, 44: PHONE_ALT_FORMAT_44, 49: PHONE_ALT_FORMAT_49, 505: PHONE_ALT_FORMAT_505, 506: PHONE_ALT_FORMAT_506, 54: PHONE_ALT_FORMAT_54, 55: PHONE_ALT_FORMAT_55, 58: PHONE_ALT_FORMAT_58, 595: PHONE_ALT_FORMAT_595, 61: PHONE_ALT_FORMAT_61, 62: PHONE_ALT_FORMAT_62, 63: PHONE_ALT_FORMAT_63, 66: PHONE_ALT_FORMAT_66, 675: PHONE_ALT_FORMAT_675, 676: PHONE_ALT_FORMAT_676, 679: PHONE_ALT_FORMAT_679, 7: PHONE_ALT_FORMAT_7, 81: PHONE_ALT_FORMAT_81, 84: PHONE_ALT_FORMAT_84, 855: PHONE_ALT_FORMAT_855, 90: PHONE_ALT_FORMAT_90, 91: PHONE_ALT_FORMAT_91, 94: PHONE_ALT_FORMAT_94, 95: PHONE_ALT_FORMAT_95, 971: PHONE_ALT_FORMAT_971, 972: PHONE_ALT_FORMAT_972, 995: PHONE_ALT_FORMAT_995}

# A mapping from a country code to the region codes which
# denote the country/region represented by that country code.
# In the case of multiple countries sharing a calling code,
# such as the NANPA countries, the one indicated with
# "main_country_for_code" in the metadata should be first.
_COUNTRY_CODE_TO_REGION_CODE = {
    1: ("US", "AG", "AI", "AS", "BB", "BM", "BS", "CA", "DM", "DO", "GD", "GU", "JM", "KN", "KY", "LC", "MP", "MS", "PR", "SX", "TC", "TT", "VC", "VG", "VI",),
    7: ("RU", "KZ",),
    20: ("EG",),
    27: ("ZA",),
    30: ("GR",),
    31: ("NL",),
    32: ("BE",),
    33: ("FR",),
    34: ("ES",),
    36: ("HU",),
    39: ("IT", "VA",),
    40: ("RO",),
    41: ("CH",),
    43: ("AT",),
    44: ("GB", "GG", "IM", "JE",),
    45: ("DK",),
    46: ("SE",),
    47: ("NO", "SJ",),
    48: ("PL",),
    49: ("DE",),
    51: ("PE",),
    52: ("MX",),
    53: ("CU",),
    54: ("AR",),
    55: ("BR",),
    56: ("CL",),
    57: ("CO",),
    58: ("VE",),
    60: ("MY",),
    61: ("AU", "CC", "CX",),
    62: ("ID",),
    63: ("PH",),
    64: ("NZ",),
    65: ("SG",),
    66: ("TH",),
    81: ("JP",),
    82: ("KR",),
    84: ("VN",),
    86: ("CN",),
    90: ("TR",),
    91: ("IN",),
    92: ("PK",),
    93: ("AF",),
    94: ("LK",),
    95: ("MM",),
    98: ("IR",),
    211: ("SS",),
    212: ("MA", "EH",),
    213: ("DZ",),
    216: ("TN",),
    218: ("LY",),
    220: ("GM",),
    221: ("SN",),
    222: ("MR",),
    223: ("ML",),
    224: ("GN",),
    225: ("CI",),
    226: ("BF",),
    227: ("NE",),
    228: ("TG",),
    229: ("BJ",),
    230: ("MU",),
    231: ("LR",),
    232: ("SL",),
    233: ("GH",),
    234: ("NG",),
    235: ("TD",),
    236: ("CF",),
    237: ("CM",),
    238: ("CV",),
    239: ("ST",),
    240: ("GQ",),
    241: ("GA",),
    242: ("CG",),
    243: ("CD",),
    244: ("AO",),
    245: ("GW",),
    246: ("IO",),
    247: ("AC",),
    248: ("SC",),
    249: ("SD",),
    250: ("RW",),
    251: ("ET",),
    252: ("SO",),
    253: ("DJ",),
    254: ("KE",),
    255: ("TZ",),
    256: ("UG",),
    257: ("BI",),
    258: ("MZ",),
    260: ("ZM",),
    261: ("MG",),
    262: ("RE", "YT",),
    263: ("ZW",),
    264: ("NA",),
    265: ("MW",),
    266: ("LS",),
    267: ("BW",),
    268: ("SZ",),
    269: ("KM",),
    290: ("SH", "TA",),
    291: ("ER",),
    297: ("AW",),
    298: ("FO",),
    299: ("GL",),
    350: ("GI",),
    351: ("PT",),
    352: ("LU",),
    353: ("IE",),
    354: ("IS",),
    355: ("AL",),
    356: ("MT",),
    357: ("CY",),
    358: ("FI", "AX",),
    359: ("BG",),
    370: ("LT",),
    371: ("LV",),
    372: ("EE",),
    373: ("MD",),
    374: ("AM",),
    375: ("BY",),
    376: ("AD",),
    377: ("MC",),
    378: ("SM",),
    380: ("UA",),
    381: ("RS",),
    382: ("ME",),
    385: ("HR",),
    386: ("SI",),
    387: ("BA",),
    389: ("MK",),
    420: ("CZ",),
    421: ("SK",),
    423: ("LI",),
    500: ("FK",),
    501: ("BZ",),
    502: ("GT",),
    503: ("SV",),
    504: ("HN",),
    505: ("NI",),
    506: ("CR",),
    507: ("PA",),
    508: ("PM",),
    509: ("HT",),
    590: ("GP", "BL", "MF",),
    591: ("BO",),
    592: ("GY",),
    593: ("EC",),
    594: ("GF",),
    595: ("PY",),
    596: ("MQ",),
    597: ("SR",),
    598: ("UY",),
    599: ("CW", "BQ",),
    670: ("TL",),
    672: ("NF",),
    673: ("BN",),
    674: ("NR",),
    675: ("PG",),
    676: ("TO",),
    677: ("SB",),
    678: ("VU",),
    679: ("FJ",),
    680: ("PW",),
    681: ("WF",),
    682: ("CK",),
    683: ("NU",),
    685: ("WS",),
    686: ("KI",),
    687: ("NC",),
    688: ("TV",),
    689: ("PF",),
    690: ("TK",),
    691: ("FM",),
    692: ("MH",),
    800: ("001",),
    808: ("001",),
    850: ("KP",),
    852: ("HK",),
    853: ("MO",),
    855: ("KH",),
    856: ("LA",),
    870: ("001",),
    878: ("001",),
    880: ("BD",),
    881: ("001",),
    882: ("001",),
    883: ("001",),
    886: ("TW",),
    888: ("001",),
    960: ("MV",),
    961: ("LB",),
    962: ("JO",),
    963: ("SY",),
    964: ("IQ",),
    965: ("KW",),
    966: ("SA",),
    967: ("YE",),
    968: ("OM",),
    970: ("PS",),
    971: ("AE",),
    972: ("IL",),
    973: ("BH",),
    974: ("QA",),
    975: ("BT",),
    976: ("MN",),
    977: ("NP",),
    979: ("001",),
    992: ("TJ",),
    993: ("TM",),
    994: ("AZ",),
    995: ("GE",),
    996: ("KG",),
    998: ("UZ",),
}
