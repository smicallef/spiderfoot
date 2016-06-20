"""Auto-generated file, do not edit by hand. MV metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MV = PhoneMetadata(id='MV', country_code=960, international_prefix='0(?:0|19)',
    general_desc=PhoneNumberDesc(national_number_pattern='[3467]\\d{6}|9(?:00\\d{7}|\\d{6})', possible_number_pattern='\\d{7,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:3(?:0[01]|3[0-59])|6(?:[567][02468]|8[024689]|90))\\d{4}', possible_number_pattern='\\d{7}', example_number='6701234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:46[46]|7[3-9]\\d|9[15-9]\\d)\\d{4}', possible_number_pattern='\\d{7}', example_number='7712345'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900\\d{7}', possible_number_pattern='\\d{10}', example_number='9001234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='781\\d{4}', possible_number_pattern='\\d{7}', example_number='7812345'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='00',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1-\\2', leading_digits_pattern=['[3467]|9(?:[1-9]|0[1-9])']),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['900'])])
