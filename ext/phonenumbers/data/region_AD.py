"""Auto-generated file, do not edit by hand. AD metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AD = PhoneMetadata(id='AD', country_code=376, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='(?:[346-9]|180)\\d{5}', possible_number_pattern='\\d{6,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='[78]\\d{5}', possible_number_pattern='\\d{6}', example_number='712345'),
    mobile=PhoneNumberDesc(national_number_pattern='[346]\\d{5}', possible_number_pattern='\\d{6}', example_number='312345'),
    toll_free=PhoneNumberDesc(national_number_pattern='180[02]\\d{4}', possible_number_pattern='\\d{8}', example_number='18001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='9\\d{5}', possible_number_pattern='\\d{6}', example_number='912345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})', format='\\1 \\2', leading_digits_pattern=['[346-9]']),
        NumberFormat(pattern='(180[02])(\\d{4})', format='\\1 \\2', leading_digits_pattern=['1'])])
