"""Auto-generated file, do not edit by hand. KI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KI = PhoneMetadata(id='KI', country_code=686, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2458]\\d{4}|3\\d{4,7}|7\\d{7}', possible_number_pattern='\\d{5,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:[24]\\d|3[1-9]|50|8[0-5])\\d{3}', possible_number_pattern='\\d{5}', example_number='31234'),
    mobile=PhoneNumberDesc(national_number_pattern='7\\d{7}', possible_number_pattern='\\d{8}', example_number='72012345'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='3001\\d{4}', possible_number_pattern='\\d{5,8}', example_number='30010000'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix_for_parsing='0')
