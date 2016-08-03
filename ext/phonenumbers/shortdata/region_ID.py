"""Auto-generated file, do not edit by hand. ID metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_ID = PhoneMetadata(id='ID', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[178]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='11[02389]', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1[02389]|40\\d{2})|71400|89887', possible_number_pattern='\\d{3,5}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='71400|89887', possible_number_pattern='\\d{5}', example_number='71400'),
    short_data=True)
