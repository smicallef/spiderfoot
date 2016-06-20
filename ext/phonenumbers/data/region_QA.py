"""Auto-generated file, do not edit by hand. QA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_QA = PhoneMetadata(id='QA', country_code=974, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-8]\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='4[04]\\d{6}', possible_number_pattern='\\d{7,8}', example_number='44123456'),
    mobile=PhoneNumberDesc(national_number_pattern='[3567]\\d{7}', possible_number_pattern='\\d{7,8}', example_number='33123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{4}', possible_number_pattern='\\d{7,8}', example_number='8001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='2(?:[12]\\d|61)\\d{4}', possible_number_pattern='\\d{7}', example_number='2123456'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([28]\\d{2})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[28]']),
        NumberFormat(pattern='([3-7]\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[3-7]'])],
    mobile_number_portable_region=True)
