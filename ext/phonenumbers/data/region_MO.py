"""Auto-generated file, do not edit by hand. MO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MO = PhoneMetadata(id='MO', country_code=853, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[268]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:28[2-57-9]|8[2-57-9]\\d)\\d{5}', possible_number_pattern='\\d{8}', example_number='28212345'),
    mobile=PhoneNumberDesc(national_number_pattern='6(?:[2356]\\d|8[158])\\d{5}', possible_number_pattern='\\d{8}', example_number='66123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([268]\\d{3})(\\d{4})', format='\\1 \\2')])
