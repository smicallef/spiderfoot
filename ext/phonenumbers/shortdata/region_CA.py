"""Auto-generated file, do not edit by hand. CA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CA = PhoneMetadata(id='CA', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[124-9]\\d{2,5}|3(?:\\d{2,5}|\\d{7})', possible_number_pattern='\\d{3,6}|\\d{8}'),
    toll_free=PhoneNumberDesc(national_number_pattern='211', possible_number_pattern='\\d{3}', example_number='211'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='112|911', possible_number_pattern='\\d{3}', example_number='911'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:12|\\d{4,5})|[25-9](?:11|\\d{4,5})|3(?:\\d{4,5}|0000\\d{3}|11)|411', possible_number_pattern='\\d{3,6}|\\d{8}', example_number='12345'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='[23567]11', possible_number_pattern='\\d{3}', example_number='611'),
    short_data=True)
