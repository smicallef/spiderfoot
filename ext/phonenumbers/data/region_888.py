"""Auto-generated file, do not edit by hand. 888 metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_888 = PhoneMetadata(id='001', country_code=888, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='\\d{11}', possible_number_pattern='\\d{11}', example_number='12345678901'),
    fixed_line=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='12345678901'),
    mobile=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='12345678901'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='\\d{11}', possible_number_pattern='\\d{11}', example_number='12345678901'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{5})', format='\\1 \\2 \\3')],
    leading_zero_possible=True)
