"""Auto-generated file, do not edit by hand. 883 metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_883 = PhoneMetadata(id='001', country_code=883, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='51\\d{7}(?:\\d{3})?', possible_number_pattern='\\d{9}(?:\\d{3})?', example_number='510012345'),
    fixed_line=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='510012345'),
    mobile=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='510012345'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='51(?:00\\d{5}(?:\\d{3})?|[13]0\\d{8})', possible_number_pattern='\\d{9}(?:\\d{3})?', example_number='510012345'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['510']),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['510']),
        NumberFormat(pattern='(\\d{4})(\\d{4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['51[13]'])])
