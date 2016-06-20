"""Auto-generated file, do not edit by hand. BY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BY = PhoneMetadata(id='BY', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2}', possible_number_pattern='\\d{3}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:0[123]|12)', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[1-79]|1[246]|35|5[1235]|6[89]|7[5-7]|8[58]|9[1-7])', possible_number_pattern='\\d{3}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
