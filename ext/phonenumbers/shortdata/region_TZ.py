"""Auto-generated file, do not edit by hand. TZ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TZ = PhoneMetadata(id='TZ', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[149]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='11[12]|999', possible_number_pattern='\\d{3}', example_number='111'),
    short_code=PhoneNumberDesc(national_number_pattern='11[12]|46400|999', possible_number_pattern='\\d{3,5}', example_number='111'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='46400', possible_number_pattern='\\d{5}', example_number='46400'),
    short_data=True)
