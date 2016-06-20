"""Auto-generated file, do not edit by hand. LS metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LS = PhoneMetadata(id='LS', country_code=266, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2568]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2\\d{7}', possible_number_pattern='\\d{8}', example_number='22123456'),
    mobile=PhoneNumberDesc(national_number_pattern='[56]\\d{7}', possible_number_pattern='\\d{8}', example_number='50123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800[256]\\d{4}', possible_number_pattern='\\d{8}', example_number='80021234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1 \\2')])
