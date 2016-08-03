"""Auto-generated file, do not edit by hand. SE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SE = PhoneMetadata(id='SE', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[1-37-9]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116\\d{3}', possible_number_pattern='\\d{6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='11811[89]|72\\d{3}', possible_number_pattern='\\d{5,6}', example_number='118118'),
    emergency=PhoneNumberDesc(national_number_pattern='112|90000', possible_number_pattern='\\d{3,5}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='11(?:[25]|313|4\\d{2}|6(?:00[06]|11[17]|123)|7[0-8]|8(?:1(?:[02-9]\\d|1[013-9])|[02-46-9]\\d{2}))|2(?:2[02358]|33|4[01]|50|6[1-4])|32[13]|7\\d{4}|8(?:22|88)|9(?:0(?:000|1(?:[02-9]\\d|1[013-9])|[2-4]\\d{2}|510)|12)', possible_number_pattern='\\d{3,6}', example_number='11313'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='2(?:2[02358]|33|4[01]|50|6[1-4])|32[13]|8(?:22|88)|912', possible_number_pattern='\\d{3}', example_number='222'),
    short_data=True)
