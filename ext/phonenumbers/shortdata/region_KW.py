"""Auto-generated file, do not edit by hand. KW metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KW = PhoneMetadata(id='KW', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[18]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='112', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1\\d{2}|89887', possible_number_pattern='\\d{3,5}', example_number='177'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='89887', possible_number_pattern='\\d{5}'),
    short_data=True)
