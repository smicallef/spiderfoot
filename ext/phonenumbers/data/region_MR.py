"""Auto-generated file, do not edit by hand. MR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MR = PhoneMetadata(id='MR', country_code=222, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-48]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='25[08]\\d{5}|35\\d{6}|45[1-7]\\d{5}', possible_number_pattern='\\d{8}', example_number='35123456'),
    mobile=PhoneNumberDesc(national_number_pattern='[234][0-46-9]\\d{6}', possible_number_pattern='\\d{8}', example_number='22123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([2-48]\\d)(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4')])
