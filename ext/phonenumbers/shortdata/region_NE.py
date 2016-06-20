"""Auto-generated file, do not edit by hand. NE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NE = PhoneMetadata(id='NE', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[1-358]\\d{1,2}|723141', possible_number_pattern='\\d{2,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1[578]|723141', possible_number_pattern='\\d{2,6}', example_number='17'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[01]|1[12]|2[034]|3[013]|40|55?|60|7|8)|222|333|555|723141|888', possible_number_pattern='\\d{2,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1(?:0[01]|1[12]|2[034]|3[013]|40|55|60)|222|333|555|888', possible_number_pattern='\\d{3}', example_number='100'),
    short_data=True)
