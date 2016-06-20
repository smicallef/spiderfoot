"""Auto-generated file, do not edit by hand. PE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PE = PhoneMetadata(id='PE', country_code=51, international_prefix='19(?:1[124]|77|90)00',
    general_desc=PhoneNumberDesc(national_number_pattern='[14-9]\\d{7,8}', possible_number_pattern='\\d{6,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1\\d|4[1-4]|5[1-46]|6[1-7]|7[2-46]|8[2-4])\\d{6}', possible_number_pattern='\\d{6,8}', example_number='11234567'),
    mobile=PhoneNumberDesc(national_number_pattern='9\\d{8}', possible_number_pattern='\\d{9}', example_number='912345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='805\\d{5}', possible_number_pattern='\\d{8}', example_number='80512345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='801\\d{5}', possible_number_pattern='\\d{8}', example_number='80112345'),
    personal_number=PhoneNumberDesc(national_number_pattern='80[24]\\d{5}', possible_number_pattern='\\d{8}', example_number='80212345'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    preferred_extn_prefix=' Anexo ',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(1)(\\d{7})', format='\\1 \\2', leading_digits_pattern=['1'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='([4-8]\\d)(\\d{6})', format='\\1 \\2', leading_digits_pattern=['[4-7]|8[2-4]'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(\\d{3})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['80'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(9\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['9'], national_prefix_formatting_rule='\\1')],
    mobile_number_portable_region=True)
