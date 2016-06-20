"""Auto-generated file, do not edit by hand. IT metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_IT = PhoneMetadata(id='IT', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[14]\\d{2,6}', possible_number_pattern='\\d{3,7}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:16\\d{3}|87)', possible_number_pattern='\\d{3,6}', example_number='187'),
    premium_rate=PhoneNumberDesc(national_number_pattern='(?:12|4(?:[478]\\d{3,5}|55))\\d{2}', possible_number_pattern='\\d{4,7}', example_number='1254'),
    emergency=PhoneNumberDesc(national_number_pattern='11[2358]', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0\\d{2,3}|1(?:[2-5789]|6(?:000|111))|2\\d{2}|3[39]|4(?:82|9\\d{1,3})|5(?:00|1[58]|2[25]|3[03]|44|[59])|60|8[67]|9(?:[01]|2(?:[01]\\d{2}|[2-9])|4\\d|696))|4(?:2323|3(?:[01]|[45]\\d{2})\\d{2}|[478](?:[0-4]|[5-9]\\d{2})\\d{2}|5(?:045|5\\d{2}))', possible_number_pattern='\\d{3,7}', example_number='114'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
