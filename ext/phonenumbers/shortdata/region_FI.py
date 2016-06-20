"""Auto-generated file, do not edit by hand. FI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FI = PhoneMetadata(id='FI', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116111', possible_number_pattern='\\d{6}', example_number='116111'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='112', possible_number_pattern='\\d{3,6}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='11(?:2|6111)', possible_number_pattern='\\d{3,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
