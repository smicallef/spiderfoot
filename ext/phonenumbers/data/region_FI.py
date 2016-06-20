"""Auto-generated file, do not edit by hand. FI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FI = PhoneMetadata(id='FI', country_code=358, international_prefix='00|99[049]',
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{4,11}|[2-9]\\d{4,10}', possible_number_pattern='\\d{5,12}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='1(?:[3569][1-8]\\d{3,9}|[47]\\d{5,10})|2[1-8]\\d{3,9}|3(?:[1-8]\\d{3,9}|9\\d{4,8})|[5689][1-8]\\d{3,9}', possible_number_pattern='\\d{5,12}', example_number='1312345678'),
    mobile=PhoneNumberDesc(national_number_pattern='4\\d{5,10}|50\\d{4,8}', possible_number_pattern='\\d{6,11}', example_number='412345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{4,7}', possible_number_pattern='\\d{7,10}', example_number='8001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='[67]00\\d{5,6}', possible_number_pattern='\\d{8,9}', example_number='600123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='[13]0\\d{4,8}|2(?:0(?:[016-8]\\d{3,7}|[2-59]\\d{2,7})|9\\d{4,8})|60(?:[12]\\d{5,6}|6\\d{7})|7(?:1\\d{7}|3\\d{8}|5[03-9]\\d{2,7})', possible_number_pattern='\\d{5,10}', example_number='10112345'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='[13]00\\d{3,7}|2(?:0(?:0\\d{3,7}|2[023]\\d{1,6}|9[89]\\d{1,6}))|60(?:[12]\\d{5,6}|6\\d{7})|7(?:1\\d{7}|3\\d{8}|5[03-9]\\d{2,7})', possible_number_pattern='\\d{5,10}', example_number='100123'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3,7})', format='\\1 \\2', leading_digits_pattern=['(?:[1-3]00|[6-8]0)'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(116\\d{3})', format='\\1', leading_digits_pattern=['116'], national_prefix_formatting_rule='\\1'),
        NumberFormat(pattern='(\\d{2})(\\d{4,10})', format='\\1 \\2', leading_digits_pattern=['[14]|2[09]|50|7[135]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d)(\\d{4,11})', format='\\1 \\2', leading_digits_pattern=['[25689][1-8]|3'], national_prefix_formatting_rule='0\\1')],
    main_country_for_code=True,
    mobile_number_portable_region=True)
