"""Auto-generated file, do not edit by hand. LR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LR = PhoneMetadata(id='LR', country_code=231, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='2\\d{7,8}|[37-9]\\d{8}|4\\d{6}|5\\d{6,8}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2\\d{7}', possible_number_pattern='\\d{8}', example_number='21234567'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:330\\d|4[67]|5\\d|77\\d{2}|88\\d{2}|994\\d)\\d{5}|(?:20\\d{3}|33(?:0\\d{2}|2(?:02|5\\d))|555\\d{2}|77[0567]\\d{2}|88[068]\\d{2}|994\\d{2})\\d{4}', possible_number_pattern='\\d{7,9}', example_number='770123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90[03]\\d{6}', possible_number_pattern='\\d{9}', example_number='900123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='332(?:0[02]|5\\d)\\d{4}', possible_number_pattern='\\d{9}', example_number='332001234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(2\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['2'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['[2579]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([4-6])(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['[4-6]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[38]'], national_prefix_formatting_rule='0\\1')])
