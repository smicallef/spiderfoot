"""Auto-generated file, do not edit by hand. IN metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_IN = PhoneMetadata(id='IN', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[125]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:0[0128]|12|298)|2611', possible_number_pattern='\\d{3,4}', example_number='108'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[0128]|12|298)|2611|53000', possible_number_pattern='\\d{3,5}', example_number='108'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='53000', possible_number_pattern='\\d{5}'),
    short_data=True)
