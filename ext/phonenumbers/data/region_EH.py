"""Auto-generated file, do not edit by hand. EH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_EH = PhoneMetadata(id='EH', country_code=212, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[5689]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='528[89]\\d{5}', possible_number_pattern='\\d{9}', example_number='528812345'),
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
    leading_digits='528[89]')
