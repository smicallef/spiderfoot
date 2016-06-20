"""Auto-generated file, do not edit by hand. GF metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GF = PhoneMetadata(id='GF', country_code=594, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[56]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='594(?:10|2[012457-9]|3[0-57-9]|4[3-9]|5[7-9]|6[0-3]|9[014])\\d{4}', possible_number_pattern='\\d{9}', example_number='594101234'),
    mobile=PhoneNumberDesc(national_number_pattern='694(?:[04][0-7]|1[0-5]|3[018]|[29]\\d)\\d{4}', possible_number_pattern='\\d{9}', example_number='694201234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', national_prefix_formatting_rule='0\\1')])
