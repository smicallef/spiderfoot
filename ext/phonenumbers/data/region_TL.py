"""Auto-generated file, do not edit by hand. TL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TL = PhoneMetadata(id='TL', country_code=670, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-489]\\d{6}|7\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2[1-5]|3[1-9]|4[1-4])\\d{5}', possible_number_pattern='\\d{7}', example_number='2112345'),
    mobile=PhoneNumberDesc(national_number_pattern='7[3-8]\\d{6}', possible_number_pattern='\\d{8}', example_number='77212345'),
    toll_free=PhoneNumberDesc(national_number_pattern='80\\d{5}', possible_number_pattern='\\d{7}', example_number='8012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90\\d{5}', possible_number_pattern='\\d{7}', example_number='9012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='70\\d{5}', possible_number_pattern='\\d{7}', example_number='7012345'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[2-489]']),
        NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['7'])])
