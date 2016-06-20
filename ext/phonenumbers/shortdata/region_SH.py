"""Auto-generated file, do not edit by hand. SH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SH = PhoneMetadata(id='SH', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='9(?:11|99)', possible_number_pattern='\\d{3}', example_number='999'),
    short_code=PhoneNumberDesc(national_number_pattern='1\\d{2,3}|9(?:11|99)', possible_number_pattern='\\d{3,4}', example_number='1234'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
