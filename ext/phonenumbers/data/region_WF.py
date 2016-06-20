"""Auto-generated file, do not edit by hand. WF metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_WF = PhoneMetadata(id='WF', country_code=681, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[4-8]\\d{5}', possible_number_pattern='\\d{6}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:50|68|72)\\d{4}', possible_number_pattern='\\d{6}', example_number='501234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:50|68|72|8[23])\\d{4}', possible_number_pattern='\\d{6}', example_number='501234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='[48]0\\d{4}', possible_number_pattern='\\d{6}', example_number='401234'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3')])
