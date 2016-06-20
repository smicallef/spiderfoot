"""Auto-generated file, do not edit by hand. SJ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SJ = PhoneMetadata(id='SJ', country_code=47, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='0\\d{4}|[4789]\\d{7}', possible_number_pattern='\\d{5}(?:\\d{3})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='79\\d{6}', possible_number_pattern='\\d{8}', example_number='79123456'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:4[015-8]|5[89]|9\\d)\\d{6}', possible_number_pattern='\\d{8}', example_number='41234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[01]\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='82[09]\\d{5}', possible_number_pattern='\\d{8}', example_number='82012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='810(?:0[0-6]|[2-8]\\d)\\d{3}', possible_number_pattern='\\d{8}', example_number='81021234'),
    personal_number=PhoneNumberDesc(national_number_pattern='880\\d{5}', possible_number_pattern='\\d{8}', example_number='88012345'),
    voip=PhoneNumberDesc(national_number_pattern='85[0-5]\\d{5}', possible_number_pattern='\\d{8}', example_number='85012345'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='0\\d{4}|81(?:0(?:0[7-9]|1\\d)|5\\d{2})\\d{3}', possible_number_pattern='\\d{5}(?:\\d{3})?', example_number='01234'),
    voicemail=PhoneNumberDesc(national_number_pattern='81[23]\\d{5}', possible_number_pattern='\\d{8}', example_number='81212345'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    leading_zero_possible=True)
