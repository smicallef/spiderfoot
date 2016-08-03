"""Auto-generated file, do not edit by hand. PK metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PK = PhoneMetadata(id='PK', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{1,3}', possible_number_pattern='\\d{2,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:1(?:22?|5)|[56])', possible_number_pattern='\\d{2,4}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1(?:22?|5)|[56])', possible_number_pattern='\\d{2,4}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
