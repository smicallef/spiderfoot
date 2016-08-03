"""Auto-generated file, do not edit by hand. NO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NO = PhoneMetadata(id='NO', country_code=47, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='0\\d{4}|[2-9]\\d{7}', possible_number_pattern='\\d{5}(?:\\d{3})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2[1-4]|3[1-3578]|5[1-35-7]|6[1-4679]|7[0-8])\\d{6}', possible_number_pattern='\\d{8}', example_number='21234567'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:4[015-8]|5[89]|87|9\\d)\\d{6}', possible_number_pattern='\\d{8}', example_number='40612345'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[01]\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='82[09]\\d{5}', possible_number_pattern='\\d{8}', example_number='82012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='810(?:0[0-6]|[2-8]\\d)\\d{3}', possible_number_pattern='\\d{8}', example_number='81021234'),
    personal_number=PhoneNumberDesc(national_number_pattern='880\\d{5}', possible_number_pattern='\\d{8}', example_number='88012345'),
    voip=PhoneNumberDesc(national_number_pattern='85[0-5]\\d{5}', possible_number_pattern='\\d{8}', example_number='85012345'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='0\\d{4}|81(?:0(?:0[7-9]|1\\d)|5\\d{2})\\d{3}', possible_number_pattern='\\d{5}(?:\\d{3})?', example_number='01234'),
    voicemail=PhoneNumberDesc(national_number_pattern='81[23]\\d{5}', possible_number_pattern='\\d{8}', example_number='81212345'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([489]\\d{2})(\\d{2})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['[489]']),
        NumberFormat(pattern='([235-7]\\d)(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[235-7]'])],
    main_country_for_code=True,
    leading_zero_possible=True,
    mobile_number_portable_region=True)
