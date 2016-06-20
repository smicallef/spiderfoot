"""Auto-generated file, do not edit by hand. SK metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SK = PhoneMetadata(id='SK', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116(?:000|111)', possible_number_pattern='\\d{6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:12|5[058])', possible_number_pattern='\\d{3,6}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1(?:2|6(?:000|111))|5[058])', possible_number_pattern='\\d{3,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
