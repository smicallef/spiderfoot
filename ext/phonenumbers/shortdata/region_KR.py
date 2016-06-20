"""Auto-generated file, do not edit by hand. KR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KR = PhoneMetadata(id='KR', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:1[78]|28|330|82)', possible_number_pattern='\\d{3,4}', example_number='118'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='11[29]', possible_number_pattern='\\d{3,4}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[01]|1[027-9]|2[01389]|3(?:2|3[039]|45|66|88|9[18])|82)', possible_number_pattern='\\d{3,4}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='10[01]', possible_number_pattern='\\d{3}', example_number='100'),
    short_data=True)
