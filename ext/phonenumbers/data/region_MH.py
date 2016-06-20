"""Auto-generated file, do not edit by hand. MH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MH = PhoneMetadata(id='MH', country_code=692, international_prefix='011',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-6]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:247|528|625)\\d{4}', possible_number_pattern='\\d{7}', example_number='2471234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:235|329|45[56]|545)\\d{4}', possible_number_pattern='\\d{7}', example_number='2351234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='635\\d{4}', possible_number_pattern='\\d{7}', example_number='6351234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='1',
    national_prefix_for_parsing='1',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1-\\2')])
