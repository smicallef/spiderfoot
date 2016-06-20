"""Auto-generated file, do not edit by hand. BN metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BN = PhoneMetadata(id='BN', country_code=673, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-578]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:[013-9]\\d|2[0-7])\\d{4}|[3-5]\\d{6}', possible_number_pattern='\\d{7}', example_number='2345678'),
    mobile=PhoneNumberDesc(national_number_pattern='22[89]\\d{4}|[78]\\d{6}', possible_number_pattern='\\d{7}', example_number='7123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([2-578]\\d{2})(\\d{4})', format='\\1 \\2')])
