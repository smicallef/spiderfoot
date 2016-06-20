"""Auto-generated file, do not edit by hand. BH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BH = PhoneMetadata(id='BH', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[89]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='999', possible_number_pattern='\\d{3}', example_number='999'),
    short_code=PhoneNumberDesc(national_number_pattern='88000|9(?:8555|99)', possible_number_pattern='\\d{3,5}', example_number='999'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='88000|98555', possible_number_pattern='\\d{5}'),
    short_data=True)
