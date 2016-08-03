"""Auto-generated file, do not edit by hand. BD metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BD = PhoneMetadata(id='BD', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='10[0-2]|999', possible_number_pattern='\\d{3}', example_number='999'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0(?:[0-39]|5(?:0\\d|[1-4])|6\\d{2}|7[0-4]|8[0-29])|1[6-9]|2(?:2[0-5]|[34])|3(?:1\\d?|3\\d|6[3-6])|4(?:0\\d|1\\d{2})|5[2-9])|9(?:594|99)', possible_number_pattern='\\d{3,5}', example_number='103'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='9594', possible_number_pattern='\\d{4}'),
    short_data=True)
