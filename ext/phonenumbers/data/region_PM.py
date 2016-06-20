"""Auto-generated file, do not edit by hand. PM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PM = PhoneMetadata(id='PM', country_code=508, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[45]\\d{5}', possible_number_pattern='\\d{6}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='41\\d{4}', possible_number_pattern='\\d{6}', example_number='411234'),
    mobile=PhoneNumberDesc(national_number_pattern='55\\d{4}', possible_number_pattern='\\d{6}', example_number='551234'),
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
    number_format=[NumberFormat(pattern='([45]\\d)(\\d{2})(\\d{2})', format='\\1 \\2 \\3', national_prefix_formatting_rule='0\\1')])
