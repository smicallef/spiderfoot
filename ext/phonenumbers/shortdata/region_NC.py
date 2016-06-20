"""Auto-generated file, do not edit by hand. NC metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NC = PhoneMetadata(id='NC', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{1,3}|3\\d{3}|5\\d{2}', possible_number_pattern='\\d{2,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='10(?:00|1[23]|3[0-2]|88)|3631|577', possible_number_pattern='\\d{3,4}', example_number='1000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1[5-8]', possible_number_pattern='\\d{2}', example_number='15'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0(?:0[06]|1[02-46]|20|3[0125]|42|5[058]|77|88)|[5-8])|3631|5[6-8]\\d', possible_number_pattern='\\d{2,4}', example_number='1000'),
    standard_rate=PhoneNumberDesc(national_number_pattern='5(?:67|88)', possible_number_pattern='\\d{3}', example_number='567'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
