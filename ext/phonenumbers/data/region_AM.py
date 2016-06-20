"""Auto-generated file, do not edit by hand. AM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AM = PhoneMetadata(id='AM', country_code=374, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{7}', possible_number_pattern='\\d{5,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1[01]\\d|2(?:2[2-46]|3[1-8]|4[2-69]|5[2-7]|6[1-9]|8[1-7])|3[12]2|47\\d)\\d{5}', possible_number_pattern='\\d{5,8}', example_number='10123456'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:4[139]|55|77|9[1-9])\\d{6}', possible_number_pattern='\\d{8}', example_number='77123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90[016]\\d{5}', possible_number_pattern='\\d{8}', example_number='90012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='80[1-4]\\d{5}', possible_number_pattern='\\d{8}', example_number='80112345'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='60[2-6]\\d{5}', possible_number_pattern='\\d{8}', example_number='60271234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{6})', format='\\1 \\2', leading_digits_pattern=['1|47'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(\\d{2})(\\d{6})', format='\\1 \\2', leading_digits_pattern=['4[139]|[5-7]|9[1-9]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['[23]'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['8|90'], national_prefix_formatting_rule='0 \\1')],
    mobile_number_portable_region=True)
