"""Auto-generated file, do not edit by hand. SO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SO = PhoneMetadata(id='SO', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[5789]\\d{2}', possible_number_pattern='\\d{3}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='555|888|999', possible_number_pattern='\\d{3}', example_number='555'),
    short_code=PhoneNumberDesc(national_number_pattern='555|777|888|999', possible_number_pattern='\\d{3}', example_number='777'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
