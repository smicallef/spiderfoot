"""Auto-generated file, do not edit by hand. CU metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CU = PhoneMetadata(id='CU', country_code=53, international_prefix='119',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-57]\\d{5,7}', possible_number_pattern='\\d{4,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2[1-4]\\d{5,6}|3(?:1\\d{6}|[23]\\d{4,6})|4(?:[125]\\d{5,6}|[36]\\d{6}|[78]\\d{4,6})|7\\d{6,7}', possible_number_pattern='\\d{4,8}', example_number='71234567'),
    mobile=PhoneNumberDesc(national_number_pattern='5\\d{7}', possible_number_pattern='\\d{8}', example_number='51234567'),
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
    number_format=[NumberFormat(pattern='(\\d)(\\d{6,7})', format='\\1 \\2', leading_digits_pattern=['7'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(\\d{2})(\\d{4,6})', format='\\1 \\2', leading_digits_pattern=['[2-4]'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(\\d)(\\d{7})', format='\\1 \\2', leading_digits_pattern=['5'], national_prefix_formatting_rule='0\\1')])
