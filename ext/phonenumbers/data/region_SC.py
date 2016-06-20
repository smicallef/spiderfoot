"""Auto-generated file, do not edit by hand. SC metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SC = PhoneMetadata(id='SC', country_code=248, international_prefix='0[0-2]',
    general_desc=PhoneNumberDesc(national_number_pattern='[2468]\\d{5,6}', possible_number_pattern='\\d{6,7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='4[2-46]\\d{5}', possible_number_pattern='\\d{7}', example_number='4217123'),
    mobile=PhoneNumberDesc(national_number_pattern='2[5-8]\\d{5}', possible_number_pattern='\\d{7}', example_number='2510123'),
    toll_free=PhoneNumberDesc(national_number_pattern='8000\\d{2}', possible_number_pattern='\\d{6}', example_number='800000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='64\\d{5}', possible_number_pattern='\\d{7}', example_number='6412345'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='00',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})', format='\\1 \\2', leading_digits_pattern=['8']),
        NumberFormat(pattern='(\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['[246]'])])
