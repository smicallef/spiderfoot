"""Auto-generated file, do not edit by hand. MA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MA = PhoneMetadata(id='MA', country_code=212, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[5689]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='5(?:2(?:(?:[015-7]\\d|2[02-9]|3[2-57]|4[2-8]|8[235-7])\\d|9(?:0\\d|[89]0))|3(?:(?:[0-4]\\d|[57][2-9]|6[235-8]|9[3-9])\\d|8(?:0\\d|[89]0)))\\d{4}', possible_number_pattern='\\d{9}', example_number='520123456'),
    mobile=PhoneNumberDesc(national_number_pattern='6(?:0[0-8]|[12-79]\\d|8[017])\\d{6}', possible_number_pattern='\\d{9}', example_number='650123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='80\\d{7}', possible_number_pattern='\\d{9}', example_number='801234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='89\\d{7}', possible_number_pattern='\\d{9}', example_number='891234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([56]\\d{2})(\\d{6})', format='\\1-\\2', leading_digits_pattern=['5(?:2[015-7]|3[0-4])|6'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([58]\\d{3})(\\d{5})', format='\\1-\\2', leading_digits_pattern=['5(?:2[2-489]|3[5-9])|892', '5(?:2(?:[2-48]|90)|3(?:[5-79]|80))|892'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(5\\d{4})(\\d{4})', format='\\1-\\2', leading_digits_pattern=['5(?:29|38)', '5(?:29|38)[89]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(8[09])(\\d{7})', format='\\1-\\2', leading_digits_pattern=['8(?:0|9[013-9])'], national_prefix_formatting_rule='0\\1')],
    main_country_for_code=True,
    mobile_number_portable_region=True)
