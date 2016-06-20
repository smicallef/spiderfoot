"""Auto-generated file, do not edit by hand. GA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GA = PhoneMetadata(id='GA', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{1,3}', possible_number_pattern='\\d{2,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:730|8|3\\d{2})', possible_number_pattern='\\d{2,4}', example_number='1730'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:730|8|3\\d{2})', possible_number_pattern='\\d{2,4}', example_number='1730'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
