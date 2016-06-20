"""Auto-generated file, do not edit by hand. SG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SG = PhoneMetadata(id='SG', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='99[359]', possible_number_pattern='\\d{3}', example_number='999'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:[0136]\\d{2}|[89](?:[1-9]\\d|0[1-9])|[57]\\d{2,3})|99[02-9]', possible_number_pattern='\\d{3,5}', example_number='1312'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
