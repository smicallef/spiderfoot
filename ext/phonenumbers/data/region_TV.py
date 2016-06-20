"""Auto-generated file, do not edit by hand. TV metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TV = PhoneMetadata(id='TV', country_code=688, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[279]\\d{4,6}', possible_number_pattern='\\d{5,7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2[02-9]\\d{3}', possible_number_pattern='\\d{5}', example_number='20123'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:70\\d|90)\\d{4}', possible_number_pattern='\\d{6,7}', example_number='901234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'))
