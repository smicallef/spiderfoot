"""Auto-generated file, do not edit by hand. FK metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FK = PhoneMetadata(id='FK', country_code=500, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-7]\\d{4}', possible_number_pattern='\\d{5}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='[2-47]\\d{4}', possible_number_pattern='\\d{5}', example_number='31234'),
    mobile=PhoneNumberDesc(national_number_pattern='[56]\\d{4}', possible_number_pattern='\\d{5}', example_number='51234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'))
