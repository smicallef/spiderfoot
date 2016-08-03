"""Auto-generated file, do not edit by hand. PL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PL = PhoneMetadata(id='PL', country_code=48, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[12]\\d{6,8}|[3-57-9]\\d{8}|6\\d{5,8}', possible_number_pattern='\\d{6,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1[2-8]|2[2-69]|3[2-4]|4[1-468]|5[24-689]|6[1-3578]|7[14-7]|8[1-79]|9[145])\\d{7}|[12]2\\d{5}', possible_number_pattern='\\d{6,9}', example_number='123456789'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:5[0137]|6[069]|7[2389]|88)\\d{7}', possible_number_pattern='\\d{9}', example_number='512345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='70\\d{7}', possible_number_pattern='\\d{9}', example_number='701234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='801\\d{6}', possible_number_pattern='\\d{9}', example_number='801234567'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='39\\d{7}', possible_number_pattern='\\d{9}', example_number='391234567'),
    pager=PhoneNumberDesc(national_number_pattern='64\\d{4,7}', possible_number_pattern='\\d{6,9}', example_number='641234567'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[14]|2[0-57-9]|3[2-4]|5[24-689]|6[1-3578]|7[14-7]|8[1-79]|9[145]']),
        NumberFormat(pattern='(\\d{2})(\\d{1})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[12]2']),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['26|39|5[0137]|6[0469]|7[02389]|8[08]']),
        NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{2,3})', format='\\1 \\2 \\3', leading_digits_pattern=['64']),
        NumberFormat(pattern='(\\d{3})(\\d{3})', format='\\1 \\2', leading_digits_pattern=['64'])],
    mobile_number_portable_region=True)
