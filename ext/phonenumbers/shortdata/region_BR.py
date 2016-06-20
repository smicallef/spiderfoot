"""Auto-generated file, do not edit by hand. BR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BR = PhoneMetadata(id='BR', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[1249]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:00|81)', possible_number_pattern='\\d{3}', example_number='181'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:12|28|9[023])|911', possible_number_pattern='\\d{3}', example_number='190'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0(?:0|[36]\\d{2}|5\\d)|[15][26]|2[38]|68|81|9[0-5789])|2(?:7(?:330|878)|85959)|40404|911', possible_number_pattern='\\d{3,6}', example_number='168'),
    standard_rate=PhoneNumberDesc(national_number_pattern='27330', possible_number_pattern='\\d{5}', example_number='27330'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='27878|40404', possible_number_pattern='\\d{5}', example_number='27878'),
    short_data=True)
