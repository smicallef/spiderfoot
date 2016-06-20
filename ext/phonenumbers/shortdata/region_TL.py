"""Auto-generated file, do not edit by hand. TL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TL = PhoneMetadata(id='TL', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2}', possible_number_pattern='\\d{3}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='11[25]', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[02]|1[25]|2[0138]|72|9[07])', possible_number_pattern='\\d{3}', example_number='102'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
