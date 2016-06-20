"""Auto-generated file, do not edit by hand. CM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CM = PhoneMetadata(id='CM', country_code=237, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2368]\\d{7,8}', possible_number_pattern='\\d{8,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:22|33|4[23])\\d{6}', possible_number_pattern='\\d{9}', example_number='222123456'),
    mobile=PhoneNumberDesc(national_number_pattern='6[5-9]\\d{7}', possible_number_pattern='\\d{9}', example_number='671234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='88\\d{6}', possible_number_pattern='\\d{8}', example_number='88012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([26])(\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4 \\5', leading_digits_pattern=['[26]']),
        NumberFormat(pattern='(\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[23]|88']),
        NumberFormat(pattern='(800)(\\d{2})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['80'])])
