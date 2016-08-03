"""Auto-generated file, do not edit by hand. LR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LR = PhoneMetadata(id='LR', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[3489]\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='355|911', possible_number_pattern='\\d{3}', example_number='911'),
    short_code=PhoneNumberDesc(national_number_pattern='355|4040|8(?:400|933)|911', possible_number_pattern='\\d{3,4}', example_number='911'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='4040|8(?:400|933)', possible_number_pattern='\\d{4}', example_number='8400'),
    short_data=True)
