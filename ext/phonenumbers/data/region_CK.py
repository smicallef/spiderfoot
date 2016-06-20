"""Auto-generated file, do not edit by hand. CK metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CK = PhoneMetadata(id='CK', country_code=682, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-8]\\d{4}', possible_number_pattern='\\d{5}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2\\d|3[13-7]|4[1-5])\\d{3}', possible_number_pattern='\\d{5}', example_number='21234'),
    mobile=PhoneNumberDesc(national_number_pattern='[5-8]\\d{4}', possible_number_pattern='\\d{5}', example_number='71234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})', format='\\1 \\2')])
