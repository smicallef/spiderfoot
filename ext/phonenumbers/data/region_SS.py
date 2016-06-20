"""Auto-generated file, do not edit by hand. SS metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SS = PhoneMetadata(id='SS', country_code=211, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='18\\d{7}', possible_number_pattern='\\d{9}', example_number='181234567'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:12|9[1257])\\d{7}', possible_number_pattern='\\d{9}', example_number='977123456'),
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
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', national_prefix_formatting_rule='0\\1')])
