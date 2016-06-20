"""Auto-generated file, do not edit by hand. KG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KG = PhoneMetadata(id='KG', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[14]\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='10[123]', possible_number_pattern='\\d{3}', example_number='101'),
    short_code=PhoneNumberDesc(national_number_pattern='10[123]|4040', possible_number_pattern='\\d{3,4}', example_number='101'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='4040', possible_number_pattern='\\d{4}'),
    short_data=True)
