"""Auto-generated file, do not edit by hand. MZ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MZ = PhoneMetadata(id='MZ', country_code=258, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[28]\\d{7,8}', possible_number_pattern='\\d{8,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:[1346]\\d|5[0-2]|[78][12]|93)\\d{5}', possible_number_pattern='\\d{8}', example_number='21123456'),
    mobile=PhoneNumberDesc(national_number_pattern='8[23467]\\d{7}', possible_number_pattern='\\d{9}', example_number='821234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([28]\\d)(\\d{3})(\\d{3,4})', format='\\1 \\2 \\3', leading_digits_pattern=['2|8[2-7]']),
        NumberFormat(pattern='(80\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['80'])])
