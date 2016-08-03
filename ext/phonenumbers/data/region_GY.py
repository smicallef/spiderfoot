"""Auto-generated file, do not edit by hand. GY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GY = PhoneMetadata(id='GY', country_code=592, international_prefix='001',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-4679]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2(?:1[6-9]|2[0-35-9]|3[1-4]|5[3-9]|6\\d|7[0-24-79])|3(?:2[25-9]|3\\d)|4(?:4[0-24]|5[56])|77[1-57])\\d{4}', possible_number_pattern='\\d{7}', example_number='2201234'),
    mobile=PhoneNumberDesc(national_number_pattern='6\\d{6}', possible_number_pattern='\\d{7}', example_number='6091234'),
    toll_free=PhoneNumberDesc(national_number_pattern='(?:289|862)\\d{4}', possible_number_pattern='\\d{7}', example_number='2891234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='9008\\d{3}', possible_number_pattern='\\d{7}', example_number='9008123'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2')])
