"""Auto-generated file, do not edit by hand. 979 metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_979 = PhoneMetadata(id='001', country_code=979, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='\\d{9}', possible_number_pattern='\\d{9}', example_number='123456789'),
    fixed_line=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='123456789'),
    mobile=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='123456789'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='\\d{9}', possible_number_pattern='\\d{9}', example_number='123456789'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d)(\\d{4})(\\d{4})', format='\\1 \\2 \\3')],
    leading_zero_possible=True)
