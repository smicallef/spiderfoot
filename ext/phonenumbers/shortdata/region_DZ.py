"""Auto-generated file, do not edit by hand. DZ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_DZ = PhoneMetadata(id='DZ', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[17]\\d{1,2}', possible_number_pattern='\\d{2,3}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1[47]', possible_number_pattern='\\d{2}', example_number='17'),
    short_code=PhoneNumberDesc(national_number_pattern='1[47]|730', possible_number_pattern='\\d{2,3}', example_number='17'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='730', possible_number_pattern='\\d{3}'),
    short_data=True)
