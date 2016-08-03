"""Auto-generated file, do not edit by hand. ER metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_ER = PhoneMetadata(id='ER', country_code=291, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[178]\\d{6}', possible_number_pattern='\\d{6,7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='1(?:1[12568]|20|40|55|6[146])\\d{4}|8\\d{6}', possible_number_pattern='\\d{6,7}', example_number='8370362'),
    mobile=PhoneNumberDesc(national_number_pattern='17[1-3]\\d{4}|7\\d{6}', possible_number_pattern='\\d{7}', example_number='7123456'),
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
    number_format=[NumberFormat(pattern='(\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', national_prefix_formatting_rule='0\\1')])
