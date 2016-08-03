"""Auto-generated file, do not edit by hand. CG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CG = PhoneMetadata(id='CG', country_code=242, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[028]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='222[1-589]\\d{5}', possible_number_pattern='\\d{9}', example_number='222123456'),
    mobile=PhoneNumberDesc(national_number_pattern='0[14-6]\\d{7}', possible_number_pattern='\\d{9}', example_number='061234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[02]']),
        NumberFormat(pattern='(\\d)(\\d{4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['8'])],
    leading_zero_possible=True)
