"""Auto-generated file, do not edit by hand. JO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_JO = PhoneMetadata(id='JO', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:12|9[127])|911', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:09|1[0-2]|9[0-24-79])|9(?:0903|11|8788)', possible_number_pattern='\\d{3,5}', example_number='111'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='9(?:0903|8788)', possible_number_pattern='\\d{5}'),
    short_data=True)
