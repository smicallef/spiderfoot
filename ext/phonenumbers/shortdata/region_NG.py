"""Auto-generated file, do not edit by hand. NG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NG = PhoneMetadata(id='NG', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[14]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='199', possible_number_pattern='\\d{3}', example_number='199'),
    short_code=PhoneNumberDesc(national_number_pattern='199|40700', possible_number_pattern='\\d{3,5}', example_number='199'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='40700', possible_number_pattern='\\d{5}', example_number='40700'),
    short_data=True)
