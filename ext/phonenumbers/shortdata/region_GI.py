"""Auto-generated file, do not edit by hand. GI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GI = PhoneMetadata(id='GI', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[158]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:00|16\\d{3}|23|47\\d|5[15]|9[2-4])|555', possible_number_pattern='\\d{3,6}', example_number='100'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:12|9[09])', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:00|1(?:2|6(?:00[06]|1(?:1[17]|23))|8\\d{2})|23|4(?:1|7[014])|5[015]|9[02349])|555|8(?:008?|4[0-2]|88)', possible_number_pattern='\\d{3,6}', example_number='116000'),
    standard_rate=PhoneNumberDesc(national_number_pattern='150', possible_number_pattern='\\d{3}', example_number='150'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1(?:18\\d{2}|23|51|9[2-4])|555|8(?:00|88)', possible_number_pattern='\\d{3,5}', example_number='123'),
    short_data=True)
