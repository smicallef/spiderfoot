"""Auto-generated file, do not edit by hand. AU metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AU = PhoneMetadata(id='AU', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[027]\\d{2}|1\\d{2,7}', possible_number_pattern='\\d{3,8}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:258885|555)|733', possible_number_pattern='\\d{3,7}', example_number='733'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1(?:2(?:34|456)|9\\d{4,6})', possible_number_pattern='\\d{4,8}', example_number='191123'),
    emergency=PhoneNumberDesc(national_number_pattern='000|1(?:06|12)', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='000|1(?:06|1(?:00|2|9[46])|2(?:[23]\\d|4\\d{2,3}|5\\d{3,4}|8(?:2|[013-9]\\d))|555|9(?:[13-5]\\d{3}|[679]\\d{5}))|225|7(?:33|67)', possible_number_pattern='\\d{3,8}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='1(?:1\\d{2}|24733)|225|767', possible_number_pattern='\\d{3,6}', example_number='225'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1(?:258885|555)', possible_number_pattern='\\d{4,7}', example_number='1555'),
    short_data=True)
