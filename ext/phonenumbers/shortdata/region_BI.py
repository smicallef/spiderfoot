"""Auto-generated file, do not edit by hand. BI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BI = PhoneMetadata(id='BI', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[16-9]\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='611', possible_number_pattern='\\d{3}', example_number='611'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='11[237]', possible_number_pattern='\\d{3}', example_number='117'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1\\d|5[2-9]|6[0-256])|611|7(?:10|77|979)|8[28]8|900', possible_number_pattern='\\d{3,4}', example_number='117'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='611|7(?:10|77)|888|900', possible_number_pattern='\\d{3}', example_number='611'),
    short_data=True)
