"""Auto-generated file, do not edit by hand. TR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TR = PhoneMetadata(id='TR', country_code=90, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-589]\\d{9}|444\\d{4}', possible_number_pattern='\\d{7,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2(?:[13][26]|[28][2468]|[45][268]|[67][246])|3(?:[13][28]|[24-6][2468]|[78][02468]|92)|4(?:[16][246]|[23578][2468]|4[26]))\\d{7}', possible_number_pattern='\\d{10}', example_number='2123456789'),
    mobile=PhoneNumberDesc(national_number_pattern='5(?:0[1-7]|22|[34]\\d|5[1-59]|9[246])\\d{7}', possible_number_pattern='\\d{10}', example_number='5012345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{7}', possible_number_pattern='\\d{10}', example_number='8001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900\\d{7}', possible_number_pattern='\\d{10}', example_number='9001234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='512\\d{7}', possible_number_pattern='\\d{10}', example_number='5123456789'),
    uan=PhoneNumberDesc(national_number_pattern='444\\d{4}|850\\d{7}', possible_number_pattern='\\d{7,10}', example_number='4441444'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='444\\d{4}', possible_number_pattern='\\d{7}', example_number='4441444'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[23]|4(?:[0-35-9]|4[0-35-9])'], national_prefix_formatting_rule='(0\\1)', national_prefix_optional_when_formatting=True),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[589]'], national_prefix_formatting_rule='0\\1', national_prefix_optional_when_formatting=True),
        NumberFormat(pattern='(444)(\\d{1})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['444'])],
    mobile_number_portable_region=True)
