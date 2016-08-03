"""Auto-generated file, do not edit by hand. SN metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SN = PhoneMetadata(id='SN', country_code=221, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[3789]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='3(?:0(?:1[0-2]|80)|282|3(?:8[1-9]|9[3-9])|611|90[1-5])\\d{5}', possible_number_pattern='\\d{9}', example_number='301012345'),
    mobile=PhoneNumberDesc(national_number_pattern='7(?:[067]\\d|21|8[0-46]|90)\\d{6}', possible_number_pattern='\\d{9}', example_number='701234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='88[4689]\\d{6}', possible_number_pattern='\\d{9}', example_number='884123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='81[02468]\\d{6}', possible_number_pattern='\\d{9}', example_number='810123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='3392\\d{5}|93330\\d{4}', possible_number_pattern='\\d{9}', example_number='933301234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[379]']),
        NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['8'])])
