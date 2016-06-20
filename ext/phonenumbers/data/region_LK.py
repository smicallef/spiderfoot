"""Auto-generated file, do not edit by hand. LK metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LK = PhoneMetadata(id='LK', country_code=94, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{8}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:[189]1|2[13-7]|3[1-8]|4[157]|5[12457]|6[35-7])[2-57]\\d{6}', possible_number_pattern='\\d{7,9}', example_number='112345678'),
    mobile=PhoneNumberDesc(national_number_pattern='7[0125-8]\\d{7}', possible_number_pattern='\\d{9}', example_number='712345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{1})(\\d{6})', format='\\1 \\2 \\3', leading_digits_pattern=['[1-689]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['7'], national_prefix_formatting_rule='0\\1')])
